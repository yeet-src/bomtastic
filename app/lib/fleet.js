"use server";

/* The fleet: every bomtastic reachable through this machine's gateway.
 *
 * Each machine runs the app as a `yeet service`: a lazy isolate whose
 * tty the gateway serves at /app, and a proxy route per peer that
 * re-roots the peer's manifest under /nodes/<host>. So one GET of the
 * local gateway's manifest lists every node's /app, however many hops
 * away, and dialing that path is dialing the node's isolate — the same
 * frames the hub speaks, relayed untouched by each gateway between.
 *
 * Nothing here reaches into a node's Node process. The isolate is the
 * only door, and `latest()` is what it answers with.
 */

const GATEWAY = process.env.BOM_GATEWAY ?? "127.0.0.1:3450";
/* Where a node's own page is, by convention: every node serves it on the same port. */
const NODE_PORT = process.env.BOM_NODE_PORT ?? "3100";
/* The service whose gateway this is, for the list of configured upstreams. */
const SERVICE = process.env.BOM_SERVICE ?? "bom-hub";
const ACTION = "app/lib/analyst.js#latest";
const TIMEOUT_MS = 20_000;

const OSC_OPEN = "\x1b]7880;";
const OSC_CLOSE = "\x07";
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* The uplink is base64url JSON lines, the downlink OSC-framed JSON —
 * the wire the hub and the isolate already share (see yeetkit's
 * bridge.mjs). Duplicated rather than imported: this file is bundled
 * into node.js and the hub is not a library. */
function encodeUplink(message) {
  const bytes = new TextEncoder().encode(JSON.stringify(message));
  let out = "";
  let bits = 0;
  let width = 0;
  for (const byte of bytes) {
    bits = (bits << 8) | byte;
    width += 8;
    while (width >= 6) {
      width -= 6;
      out += B64[(bits >> width) & 0x3f];
    }
  }
  if (width > 0) out += B64[(bits << (6 - width)) & 0x3f];
  /* Bytes, not a string: the tty portal takes binary frames and drops
   * text ones on the floor. */
  return new TextEncoder().encode(`${out}\n`);
}

/** One call to a "use yeet" function on the isolate behind `url`. */
function callRoute(url, action, args = []) {
  return new Promise((resolve, reject) => {
    const cid = `h:fleet:${Date.now()}:${Math.random().toString(36).slice(2, 8)}`;
    const socket = new WebSocket(url);
    socket.binaryType = "arraybuffer";
    let pending = "";
    const done = (fn, value) => {
      clearTimeout(timer);
      try {
        socket.close();
      } catch {}
      fn(value);
    };
    const timer = setTimeout(() => done(reject, new Error(`timed out after ${TIMEOUT_MS / 1000}s`)), TIMEOUT_MS);

    socket.addEventListener("open", () => socket.send(encodeUplink({ t: "call", cid, action, args })));
    socket.addEventListener("error", () => done(reject, new Error("could not connect")));
    socket.addEventListener("close", (e) => {
      if (timer) done(reject, new Error(`route closed (${e.code})`));
    });
    socket.addEventListener("message", (event) => {
      pending += typeof event.data === "string" ? event.data : new TextDecoder().decode(new Uint8Array(event.data));
      for (;;) {
        const start = pending.indexOf(OSC_OPEN);
        if (start < 0) return;
        const end = pending.indexOf(OSC_CLOSE, start);
        if (end < 0) return;
        const body = pending.slice(start + OSC_OPEN.length, end);
        pending = pending.slice(end + OSC_CLOSE.length);
        let frame;
        try {
          frame = JSON.parse(body);
        } catch {
          continue;
        }
        /* The tty is shared with the node's own hub, so most of what
         * arrives is someone else's: view patches, other replies. Only
         * the reply to this cid is ours. */
        if (frame.op === "return" && frame.cid === cid) {
          frame.error ? done(reject, new Error(frame.error)) : done(resolve, frame.value);
          return;
        }
      }
    });
  });
}

/* Red, amber, green — the same rule for every node, from the same
 * deterministic data the inventory page shows. */
const RANK = { critical: 3, important: 3, high: 3, moderate: 2, medium: 2, low: 1 };

function verdict(inv) {
  const advisories = inv.vulns?.advisories ?? [];
  const worst = Math.max(0, ...advisories.map((a) => RANK[a.severity?.toLowerCase()] ?? 1));
  const high = inv.findings.filter((f) => f.severity === "high");
  const exposed = advisories.filter((a) => (a.processes ?? []).some((p) => p.listener || p.wildcard)).length;
  if (worst >= 3 || high.length > 0) {
    return {
      level: "red",
      text:
        worst >= 3
          ? `${advisories.filter((a) => (RANK[a.severity?.toLowerCase()] ?? 0) >= 3).length} high-severity advisories on running software${exposed ? `, ${exposed} network-facing` : ""}`
          : `${high.length} high finding${high.length === 1 ? "" : "s"}`,
    };
  }
  if (advisories.length > 0 || inv.findings.some((f) => f.severity === "medium")) {
    return {
      level: "amber",
      text: advisories.length
        ? `${advisories.length} pending advisor${advisories.length === 1 ? "y" : "ies"}, none rated high`
        : `${inv.findings.filter((f) => f.severity === "medium").length} medium findings`,
    };
  }
  return { level: "green", text: "nothing pending" };
}

/* A node is known by the segment its proxy route gives it — the peer's
 * address with dots as dashes, as conf.js writes it — and that segment
 * is the slug of its drill-down page. */
function identify(route) {
  const m = /^\/nodes\/([^/]+)\//.exec(route.path);
  if (!m) return { slug: "local", name: "this host", address: null, ui: null, local: true };
  const address = m[1].replaceAll("-", ".");
  return { slug: m[1], name: address, address, ui: `http://${address}:${NODE_PORT}/`, local: false };
}

/* What a drill-down page needs from a node, and no more: the process
 * list is cut to what the tables reference, the file map and the
 * binary/library tables stay on the node. */
function trim(inv) {
  return {
    startedAt: inv.startedAt,
    host: inv.host,
    counts: inv.counts,
    changes: inv.changes ?? null,
    findings: inv.findings,
    listeners: inv.listeners,
    outbound: inv.outbound.slice(0, 40),
    containers: inv.containers,
    vulns: { source: inv.vulns?.source ?? null, error: inv.vulns?.error ?? null, advisories: inv.vulns?.advisories ?? [] },
    processes: inv.processes.map((p) => ({ pid: p.pid, comm: p.comm, uid: p.uid, exe: p.exe, container: p.container ?? null })),
  };
}

/** The routes to walk: one per node, from the gateway's manifest. Fast,
 * so the page can show every node as pending before any has answered. */
export async function fleetRoutes() {
  let manifest;
  try {
    const response = await fetch(`http://${GATEWAY}/.well-known/yeet/manifest.json`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    manifest = await response.json();
  } catch (error) {
    return { gateway: GATEWAY, error: `no gateway at ${GATEWAY}: ${error.message}. Is the bom service running?`, routes: [] };
  }
  const routes = manifest.routes
    .filter((r) => r.kind === "isolate" && r.portal === "tty" && r.path.endsWith("/app"))
    .map((route) => ({ path: route.path, hops: route.via?.length ?? 1, ...identify(route) }));

  /* A proxy route whose upstream is down is simply absent from the
   * manifest (and `partial` stays false), so a dead node would vanish
   * rather than show as unreachable. The service definition still knows
   * every upstream this gateway was told about; anything configured but
   * not answering gets a row of its own, and its dial fails on its own. */
  for (const prefix of await configuredUpstreams()) {
    const path = `${prefix}/app`;
    if (!routes.some((r) => r.path === path)) routes.push({ path, hops: 2, configured: true, ...identify({ path }) });
  }
  return { gateway: GATEWAY, partial: manifest.partial, routes };
}

async function configuredUpstreams() {
  try {
    const { execFile } = await import("node:child_process");
    const json = await new Promise((resolve, reject) =>
      execFile("yeet", ["service", "export", SERVICE, "-j"], { timeout: 5000 }, (error, stdout) => (error ? reject(error) : resolve(stdout))),
    );
    const units = Object.values(JSON.parse(json).units ?? {});
    return units.flatMap((u) => Object.entries(u.routes ?? {}).filter(([, r]) => r.upstream).map(([path]) => path.replace(/\/$/, "")));
  } catch {
    return [];
  }
}

/** One node's row: dial its route, ask for the latest scan, judge it.
 * Called once per route by the isolate, concurrently, so a slow or dead
 * node delays its own row and nobody else's. */
export async function fleetNode(path) {
  const t0 = Date.now();
  try {
    const inv = await callRoute(`ws://${GATEWAY}${path}`, ACTION);
    if (!inv) throw new Error("scan failed on the node");
    const top = (inv.vulns?.advisories ?? [])
      .slice()
      .sort((a, b) => (RANK[b.severity?.toLowerCase()] ?? 0) - (RANK[a.severity?.toLowerCase()] ?? 0))
      .slice(0, 3)
      .map((a) => ({ id: a.id, severity: a.severity, packages: a.packages.map((p) => p.name) }));
    return {
      ok: true,
      ms: Date.now() - t0,
      host: inv.host,
      startedAt: inv.startedAt,
      counts: inv.counts,
      changes: inv.changes?.summary ?? null,
      verdict: verdict(inv),
      top,
      highFindings: inv.findings.filter((f) => f.severity === "high").map((f) => f.title),
      inventory: trim(inv),
    };
  } catch (error) {
    return { ok: false, ms: Date.now() - t0, error: error.message, verdict: { level: "grey", text: "unreachable" } };
  }
}

/** The whole walk in one call, for anything that wants it all at once. */
export async function fleet() {
  const { routes, ...rest } = await fleetRoutes();
  const nodes = await Promise.all(routes.map(async (route) => ({ ...route, ...(await fleetNode(route.path)) })));
  const order = { red: 0, amber: 1, grey: 2, green: 3 };
  nodes.sort((a, b) => order[a.verdict.level] - order[b.verdict.level] || a.name.localeCompare(b.name));
  return { ...rest, nodes };
}
