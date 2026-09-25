/* The runtime bill of materials: what is actually executing on this
 * host right now, built from /proc rather than from a build manifest.
 *
 * Plain isolate module — no directive — so a page imports the signals
 * directly and the AI analyst reads the same object. The scan is one
 * shared thing: every tab sees the same inventory, and a rescan from
 * any tab refreshes all of them.
 *
 * Two runtimes contribute. The isolate walks /proc through sys_graph:
 * binaries, mapped libraries, sockets, cgroups. Node — the "use server"
 * side in enrich.js — answers the questions only a filesystem can:
 * which package owns a file, and what its hash is.
 */
import { createSignal } from "yeetkit";

import { advisories } from "@/lib/advisories.js";
import { enrich, hostIdentity } from "@/lib/enrich.js";
import { saveScan } from "@/lib/history.js";
import { walk } from "@/lib/walk.js";

export const [inventory, setInventory] = createSignal(null);
export const [scanning, setScanning] = createSignal(false);
export const [scanError, setScanError] = createSignal(null);
export const [progress, setProgress] = createSignal("");

let running = null;

/** Run a scan, or join the one in flight. */
export function scan() {
  if (running) return running;
  running = (async () => {
    setScanning(true);
    setScanError(null);
    try {
      let next;
      /* A few full passes if a process vanished mid-walk and every retry
       * inside the query lost the race too; a failed pass keeps the
       * previous inventory on the page rather than blanking it. */
      for (let pass = 1; ; pass++) {
        try {
          next = await build();
          break;
        } catch (error) {
          if (pass >= 3 || !/File not found: \/proc\//.test(String(error?.message))) throw error;
          setProgress(`a process exited mid-scan, pass ${pass + 1}…`);
        }
      }
      setInventory(next);
      console.log(`scan: ${JSON.stringify(next.timings)}`);
    } catch (error) {
      setScanError(String(error?.message ?? error));
      console.error(`scan failed: ${error?.stack ?? error}`);
    } finally {
      setScanning(false);
      setProgress("");
      running = null;
    }
  })();
  return running;
}

/* ---- collection -------------------------------------------------- */

const PRIVATE = /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.0\.0\.0|::1?$|\[::|fe80|fd|fc)/;
const SUSPECT_DIRS = /^\/(tmp|var\/tmp|dev\/shm|run\/user)\//;
const isFile = (path) => path.startsWith("/") && !/^\/(memfd:|dev\/|SYSV|anon_hugepage|i915|drm)/.test(path);
const isLibrary = (path) => /\.so(\.|$)/.test(path);

/* Prefer the Worker; fall back to walking inline when the bundled
 * worker script is missing (a dev tree before `npm run worker`) or the
 * runtime has no `Worker`. A failure *inside* the walk is not a worker
 * problem and propagates as-is, so scan()'s /proc-race retry still sees
 * the daemon's message. */
let workerBroken = typeof Worker !== "function";

/* A worker whose JS thread dies at startup reports nothing to its opener
 * (seen with yeet 0.23 on the first load of a freshly built script:
 * `yeet ps` lists it, `yeet attach` says "JS thread gone", no `error`
 * event). The walk posts its first progress line within milliseconds,
 * so silence this long means the worker is not coming back. */
const WORKER_SILENCE_MS = 5_000;

async function walkInWorker() {
  if (workerBroken) return walk(setProgress);
  try {
    return await new Promise((resolve, reject) => {
      const w = new Worker("./scan-worker.js");
      const chunks = [];
      let timer = null;
      const dead = (why) => { clearTimeout(timer); w.terminate(); reject(Object.assign(new Error(why), { worker: true })); };
      const alive = () => { clearTimeout(timer); timer = setTimeout(() => dead(`scan worker went silent for ${WORKER_SILENCE_MS} ms`), WORKER_SILENCE_MS); };
      alive();
      w.onmessage = (event) => {
        alive();
        /* Reading `data` can itself throw — the runtime raises its
         * message-size limit here, on the receiving side — and a throw
         * out of this handler would settle nothing, so it is a death. */
        try {
          const { data } = event;
          if (data.progress) setProgress(data.progress);
          else if (data.chunk != null) {
            chunks[data.index] = data.chunk;
            if (chunks.filter((c) => c != null).length === data.total) { clearTimeout(timer); w.terminate(); resolve(JSON.parse(chunks.join(""))); }
          } else if (data.error) { clearTimeout(timer); w.terminate(); reject(new Error(data.error)); }
        } catch (error) {
          dead(`scan worker message failed: ${error?.message ?? error}`);
        }
      };
      w.onerror = (e) => dead(e.message ?? "scan worker failed");
    });
  } catch (error) {
    if (!error.worker) throw error;
    workerBroken = true;
    console.warn(`scan worker unavailable, walking inline: ${error.message}`);
    return walk(setProgress);
  }
}

async function build() {
  const startedAt = new Date().toISOString();
  const t0 = Date.now();
  const timings = {};
  let mark = t0;
  const lap = (name) => { const now = Date.now(); timings[name] = now - mark; mark = now; };

  /* The /proc walk runs in a Worker: a second isolate that does the
   * queries and the first fold, posts the compact result back, and is
   * terminated — its map tables go with it, and this isolate never
   * blocks while the daemon walks a few hundred processes. */
  const raw = await walkInWorker();
  Object.assign(timings, raw.timings);
  mark = Date.now();
  const { procs, host, net, containers } = raw;
  const libsByPid = new Map(raw.libsByPid);
  const pidByInode = new Map(raw.pidByInode);
  /* Only processes with a binary: kernel threads have no exe and are
   * not software anyone shipped. */
  const processes = procs
    .filter((p) => p.exe)
    .map((p) => {
      const cg = p.cgroups?.[0]?.pathname ?? "";
      const containerId = /(docker|libpod|containerd)[-/]([0-9a-f]{12,64})/.exec(cg)?.[2]?.slice(0, 12) ?? null;
      const deleted = p.exe.endsWith(" (deleted)");
      const libs = libsByPid.get(p.pid) ?? [];
      return {
        pid: p.pid,
        ppid: p.stat?.ppid ?? 0,
        comm: p.stat?.comm ?? "?",
        uid: p.uid,
        exe: deleted ? p.exe.slice(0, -" (deleted)".length) : p.exe,
        exe_deleted: deleted,
        cwd: p.cwd,
        cmdline: p.cmdline.join(" "),
        rss: p.stat?.rss_bytes ?? 0,
        started: host.boot_time_secs + Math.floor((p.stat?.starttime ?? 0) / host.ticks_per_second),
        container: containerId,
        cgroup: cg,
        libs: libs.filter((l) => isFile(l) && !l.endsWith(" (deleted)")),
        /* memfd:, /dev/zero and SysV shm mappings always read as
         * "(deleted)"; only a real path that vanished is a stale copy. */
        stale_libs: libs
          .filter((l) => isFile(l) && l.endsWith(" (deleted)"))
          .map((l) => l.slice(0, -" (deleted)".length)),
      };
    });
  const byPid = new Map(processes.map((p) => [p.pid, p]));

  const sockets = [...net.tcp, ...net.tcp6];
  const listeners = sockets
    .filter((s) => s.state === "Listen")
    .map((s) => ({ ...owned(s, pidByInode, byPid), proto: "tcp" }))
    .concat(
      [...net.udp, ...net.udp6].map((s) => ({ ...owned({ ...s, remote_address: { addr: "" } }, pidByInode, byPid), proto: "udp" })),
    )
    .sort((a, b) => a.port - b.port);
  const outbound = sockets
    .filter((s) => s.state === "Established" && !PRIVATE.test(s.remote_address.addr))
    .map((s) => owned(s, pidByInode, byPid));

  /* Node's turn: package ownership and hashes for everything a host
   * process has mapped. Container paths are skipped — they resolve
   * against a different root, so the host's package database has no
   * opinion about them. */
  const hostProcs = processes.filter((p) => !p.container);
  const paths = new Set();
  for (const p of hostProcs) {
    paths.add(p.exe);
    for (const l of p.libs) paths.add(l);
  }
  const exes = [...new Set(hostProcs.map((p) => p.exe))];
  setProgress(`asking the package manager about ${paths.size} files`);
  let files = {};
  let enrichError = null;
  try {
    files = await enrich({ paths: [...paths], hash: exes });
  } catch (error) {
    /* The inventory is still useful without packages and hashes, so
     * this degrades rather than fails — but loudly, because a silent
     * "everything is unpackaged" is a wrong answer, not a partial one. */
    console.error(`enrichment failed: ${error?.message ?? error}`);
    enrichError = String(error?.message ?? error);
  }

  lap("enrich");

  /* Pending security advisories for the packages in use. Node asks the
   * package manager (or OSV) and looks the CVEs up; here it becomes a
   * finding and a per-package index the tables read. */
  setProgress("checking security advisories");
  let vulns = { source: null, advisories: [], byPackage: {} };
  try {
    const inUse = [...new Set(Object.values(files).map((f) => f.package).filter(Boolean))];
    vulns = await advisories({ packages: inUse });
  } catch (error) {
    vulns.error = String(error?.message ?? error);
  }
  lap("advisories");

  /* The bill of materials proper: one row per distinct binary, and one
   * per distinct library, each with who runs it. */
  const binaries = group(processes, (p) => p.exe, files);
  const libraries = group(
    processes.flatMap((p) => p.libs.filter((l) => l !== p.exe && isLibrary(l)).map((l) => ({ ...p, key: l }))),
    (r) => r.key,
    files,
  );

  /* Which processes run each advisory's packages, by package name. */
  const pkgName = (pkg) => pkg?.split(" ")[0];
  const procsByPkg = new Map();
  for (const p of processes) {
    if (p.container) continue;
    const names = new Set([pkgName(files[p.exe]?.package), ...p.libs.map((l) => pkgName(files[l]?.package))].filter(Boolean));
    for (const n of names) (procsByPkg.get(n) ?? procsByPkg.set(n, []).get(n)).push(p);
  }
  for (const a of vulns.advisories) {
    const affected = new Map();
    for (const pk of a.packages) for (const p of procsByPkg.get(pk.name) ?? []) affected.set(p.pid, p);
    a.processes = [...affected.values()].map((p) => ({ pid: p.pid, comm: p.comm })).sort((x, y) => x.pid - y.pid);
  }

  const findings = judge({ processes, listeners, outbound, files, containers, vulns });
  lap("findings");

  /* History: save a compact snapshot in Node and diff against the one
   * before it. The diff is what turns findings into "since when". */
  setProgress("comparing with the previous scan");
  let changes = null;
  let history = null;
  try {
    const snapshot = snapshotOf({ startedAt, processes, binaries, listeners, outbound, vulns, findings, files });
    const { previous, kept } = await saveScan(snapshot);
    history = { kept, previousAt: previous?.at ?? null };
    if (previous) changes = diffScans(previous, snapshot);
  } catch (error) {
    history = { error: String(error?.message ?? error) };
  }
  lap("history");
  /* Who this is, for the fleet page: a node's inventory travels to a
   * hub that knows it only by a route. */
  const identity = await hostIdentity().catch((error) => {
    console.log(`scan: hostIdentity failed: ${error?.message ?? error}`);
    return {};
  });
  timings.total = Date.now() - t0;

  return {
    startedAt,
    host: { boot_time: host.boot_time_secs, ...identity },
    timings,
    changes,
    history,
    enrichError,
    counts: {
      processes: processes.length,
      binaries: binaries.length,
      libraries: libraries.length,
      listeners: listeners.length,
      outbound: outbound.length,
      containers: containers.length,
      unpackaged: binaries.filter((b) => b.package === null && !b.container).length,
      findings: findings.length,
      high: findings.filter((f) => f.severity === "high").length,
      advisories: vulns.advisories.length,
      cves: new Set(vulns.advisories.flatMap((a) => a.cves.map((c) => c.id))).size,
    },
    vulns,
    processes,
    binaries,
    libraries,
    listeners,
    outbound,
    containers,
    findings,
    files,
  };
}

function owned(s, pidByInode, byPid) {
  const pid = pidByInode.get(s.inode) ?? null;
  const proc = pid ? byPid.get(pid) : null;
  const local = s.local_address.addr;
  return {
    local,
    remote: s.remote_address.addr,
    port: Number(local.slice(local.lastIndexOf(":") + 1)),
    wildcard: /^(0\.0\.0\.0|\[::\]|::):/.test(local),
    uid: s.uid,
    pid,
    comm: proc?.comm ?? null,
    exe: proc?.exe ?? null,
    container: proc?.container ?? null,
  };
}

function group(rows, keyOf, files) {
  const out = new Map();
  for (const r of rows) {
    const key = keyOf(r);
    let g = out.get(key);
    if (!g) {
      const f = files[key] ?? {};
      g = {
        path: key,
        package: f.package ?? null,
        sha256: f.sha256 ?? null,
        mtime: f.mtime ?? null,
        pids: [],
        comms: new Set(),
        container: r.container,
      };
      out.set(key, g);
    }
    g.pids.push(r.pid);
    g.comms.add(r.comm);
  }
  return [...out.values()]
    .map((g) => ({ ...g, comms: [...g.comms].sort(), pids: [...new Set(g.pids)].sort((a, b) => a - b) }))
    .sort((a, b) => b.pids.length - a.pids.length || a.path.localeCompare(b.path));
}

/* ---- findings ---------------------------------------------------- *
 *
 * Deterministic and evidence-first. Each finding names the pids and
 * the fact that produced it, so it can be checked by hand — the model
 * ranks and explains these, it does not invent them.
 */
function judge({ processes, listeners, outbound, files, vulns }) {
  const findings = [];
  const add = (severity, kind, title, detail, pids) =>
    findings.push({ severity, kind, title, detail, pids: [...new Set(pids)].sort((a, b) => a - b) });

  const advs = vulns?.advisories ?? [];
  if (advs.length) {
    const worst = advs[0].severity?.toLowerCase();
    const severity = worst === "critical" || worst === "important" || worst === "high" ? "high" : worst === "moderate" || worst === "medium" ? "medium" : "info";
    const cves = new Set(advs.flatMap((a) => a.cves.map((c) => c.id)));
    const pkgs = new Set(advs.flatMap((a) => a.packages.map((p) => p.name)));
    add(
      severity,
      "security-update",
      `${advs.length} pending security advisor${advs.length > 1 ? "ies" : "y"} for packages in use (${cves.size} CVE${cves.size === 1 ? "" : "s"})`,
      `The fix is published but not installed, so running processes still carry the hole. ${[...pkgs].slice(0, 8).join(", ")}${pkgs.size > 8 ? ` … +${pkgs.size - 8}` : ""}. Worst: ${advs[0].severity} — ${advs[0].title}${advs[0].cves[0]?.score != null ? ` (CVSS ${advs[0].cves[0].score})` : ""}. See the advisories table.`,
      advs.flatMap((a) => a.processes?.map((p) => p.pid) ?? []),
    );
  } else if (vulns?.source && !vulns.error) {
    add("info", "security-update", "No pending security advisories for packages in use", `Checked ${vulns.source === "dnf" ? "the distribution's update feed" : "OSV"} for every packaged binary and library a live process maps.`, []);
  }

  const stale = processes.filter((p) => p.exe_deleted);
  if (stale.length)
    add(
      "medium",
      "stale-binary",
      `${stale.length} process${stale.length > 1 ? "es" : ""} running a binary that was replaced on disk`,
      "The file was updated or removed after the process started — it is executing code that no longer exists on disk, so a patch has not taken effect. Restart to pick up the new version: " +
        stale.map((p) => `${p.comm}(${p.pid}) ${p.exe}`).join("; "),
      stale.map((p) => p.pid),
    );

  const staleLibs = processes.filter((p) => p.stale_libs.length && !p.exe_deleted);
  if (staleLibs.length)
    add(
      "medium",
      "stale-library",
      `${staleLibs.length} process${staleLibs.length > 1 ? "es" : ""} still mapping a shared library that was updated`,
      "A library update landed but these processes hold the old copy in memory. Typical after a glibc or openssl patch without a restart: " +
        staleLibs.slice(0, 8).map((p) => `${p.comm}(${p.pid}) → ${p.stale_libs.slice(0, 2).join(", ")}`).join("; "),
      staleLibs.map((p) => p.pid),
    );

  const suspect = processes.filter((p) => SUSPECT_DIRS.test(p.exe));
  if (suspect.length)
    add(
      "high",
      "exe-in-temp",
      `${suspect.length} process${suspect.length > 1 ? "es" : ""} executing from a temporary or shared-memory directory`,
      "Binaries in /tmp, /var/tmp or /dev/shm are not how software is installed; this is the most common signature of a dropped payload. " +
        suspect.map((p) => `${p.comm}(${p.pid}) ${p.exe}`).join("; "),
      suspect.map((p) => p.pid),
    );

  const unpackaged = processes.filter(
    (p) => !p.container && files[p.exe] && files[p.exe].package === null && !SUSPECT_DIRS.test(p.exe),
  );
  const unpackagedExes = [...new Set(unpackaged.map((p) => p.exe))];
  if (unpackagedExes.length)
    add(
      "info",
      "unpackaged",
      `${unpackagedExes.length} running binar${unpackagedExes.length > 1 ? "ies" : "y"} not owned by any package`,
      "These are not in the package manager's database, so they are invisible to a build-time SBOM and to `rpm -qa`/`dpkg -l` based scanners. They came from a language runtime, a manual install, or a build tree: " +
        unpackagedExes.slice(0, 10).join(", ") + (unpackagedExes.length > 10 ? ` … +${unpackagedExes.length - 10}` : ""),
      unpackaged.map((p) => p.pid),
    );

  const rootWild = listeners.filter((l) => l.wildcard && l.uid === 0 && l.proto === "tcp");
  if (rootWild.length)
    add(
      "medium",
      "root-listener",
      `${new Set(rootWild.map((l) => `${l.pid}:${l.port}`)).size} root-owned port${new Set(rootWild.map((l) => `${l.pid}:${l.port}`)).size > 1 ? "s" : ""} listening on every interface`,
      "A root process bound to 0.0.0.0 or [::] is reachable from any network the host is on and runs with full privilege: " +
        [...new Set(rootWild.map((l) => `${l.comm ?? "?"}(${l.pid ?? "?"}) :${l.port}`))].join(", "),
      rootWild.map((l) => l.pid).filter(Boolean),
    );

  const unattributed = listeners.filter((l) => l.pid === null && l.proto === "tcp");
  if (unattributed.length)
    add(
      "info",
      "unattributed-listener",
      `${unattributed.length} listening socket${unattributed.length > 1 ? "s" : ""} with no visible owner`,
      "No process in this view holds the socket's inode — usually a process in another pid namespace or one this scan lacked permission to read: " +
        unattributed.map((l) => `${l.proto} ${l.local}`).join(", "),
      [],
    );

  const external = new Map();
  for (const c of outbound) {
    const k = c.comm ?? "unknown";
    external.set(k, (external.get(k) ?? 0) + 1);
  }
  if (outbound.length)
    add(
      "info",
      "outbound",
      `${outbound.length} established connection${outbound.length > 1 ? "s" : ""} to non-private addresses`,
      "What this host is talking to right now, by process: " +
        [...external.entries()].sort((a, b) => b[1] - a[1]).map(([k, n]) => `${k} ×${n}`).join(", "),
      outbound.map((c) => c.pid).filter(Boolean),
    );

  const order = { high: 0, medium: 1, info: 2 };
  return findings.sort((a, b) => order[a.severity] - order[b.severity]);
}


/* ---- history ------------------------------------------------------ *
 *
 * A snapshot is what a diff needs and nothing more: identities and the
 * few facts whose change means something. Processes are keyed by pid
 * plus start time, so a recycled pid is a new process.
 */
function snapshotOf({ startedAt, processes, binaries, listeners, outbound, vulns, findings, files }) {
  return {
    at: startedAt,
    processes: processes.map((p) => ({ key: `${p.pid}:${p.started}`, pid: p.pid, comm: p.comm, exe: p.exe, uid: p.uid, container: p.container })),
    binaries: binaries.map((b) => ({ path: b.path, sha256: b.sha256, package: b.package, procs: b.pids.length })),
    listeners: listeners.map((l) => ({ key: `${l.proto} ${l.local}`, pid: l.pid, comm: l.comm })),
    peers: [...new Set(outbound.map((c) => `${c.comm ?? "?"} → ${c.remote.replace(/:\d+$/, "")}`))],
    advisories: (vulns?.advisories ?? []).map((a) => ({ id: a.id, severity: a.severity, title: a.title })),
    findings: findings.map((f) => `${f.kind}:${f.severity}`),
    packages: Object.fromEntries(Object.entries(files).filter(([, f]) => f.package).map(([path, f]) => [path, f.package])),
  };
}

function diffScans(prev, cur) {
  const by = (rows, k) => new Map(rows.map((r) => [r[k], r]));
  const added = (a, b, k) => [...by(b, k).keys()].filter((x) => !by(a, k).has(x)).map((x) => by(b, k).get(x));
  const removed = (a, b, k) => [...by(a, k).keys()].filter((x) => !by(b, k).has(x)).map((x) => by(a, k).get(x));

  const procsNew = added(prev.processes, cur.processes, "key").filter((p) => !p.container);
  const procsGone = removed(prev.processes, cur.processes, "key").filter((p) => !p.container);
  const binsNew = added(prev.binaries, cur.binaries, "path");
  const binsGone = removed(prev.binaries, cur.binaries, "path");
  const prevBins = by(prev.binaries, "path");
  const hashChanged = cur.binaries.filter((b) => b.sha256 && prevBins.get(b.path)?.sha256 && prevBins.get(b.path).sha256 !== b.sha256).map((b) => ({ path: b.path, from: prevBins.get(b.path).sha256.slice(0, 12), to: b.sha256.slice(0, 12) }));
  const pkgChanged = Object.entries(cur.packages ?? {}).filter(([path, pkg]) => prev.packages?.[path] && prev.packages[path] !== pkg).map(([path, pkg]) => ({ path, from: prev.packages[path], to: pkg }));
  const listenNew = added(prev.listeners, cur.listeners, "key");
  const listenGone = removed(prev.listeners, cur.listeners, "key");
  const peersNew = cur.peers.filter((p) => !prev.peers.includes(p));
  const peersGone = prev.peers.filter((p) => !cur.peers.includes(p));
  const advNew = added(prev.advisories, cur.advisories, "id");
  const advFixed = removed(prev.advisories, cur.advisories, "id");

  const seconds = Math.max(0, Math.round((Date.parse(cur.at) - Date.parse(prev.at)) / 1000));
  const parts = [];
  if (procsNew.length) parts.push(`${procsNew.length} new process${procsNew.length > 1 ? "es" : ""}`);
  if (procsGone.length) parts.push(`${procsGone.length} exited`);
  if (binsNew.length) parts.push(`${binsNew.length} new binar${binsNew.length > 1 ? "ies" : "y"}`);
  if (hashChanged.length) parts.push(`${hashChanged.length} binar${hashChanged.length > 1 ? "ies" : "y"} changed on disk`);
  if (pkgChanged.length) parts.push(`${pkgChanged.length} package${pkgChanged.length > 1 ? "s" : ""} upgraded`);
  if (listenNew.length) parts.push(`${listenNew.length} new listener${listenNew.length > 1 ? "s" : ""}`);
  if (listenGone.length) parts.push(`${listenGone.length} listener${listenGone.length > 1 ? "s" : ""} closed`);
  if (peersNew.length) parts.push(`${peersNew.length} new outbound peer${peersNew.length > 1 ? "s" : ""}`);
  if (advNew.length) parts.push(`${advNew.length} new advisor${advNew.length > 1 ? "ies" : "y"}`);
  if (advFixed.length) parts.push(`${advFixed.length} advisor${advFixed.length > 1 ? "ies" : "y"} fixed`);

  return {
    since: prev.at,
    seconds,
    quiet: parts.length === 0,
    summary: parts.length ? parts.join(", ") : "nothing changed",
    processes: { started: procsNew.slice(0, 40), exited: procsGone.slice(0, 40) },
    binaries: { appeared: binsNew.slice(0, 40), gone: binsGone.slice(0, 40), hashChanged: hashChanged.slice(0, 40), packageChanged: pkgChanged.slice(0, 40) },
    listeners: { opened: listenNew, closed: listenGone },
    peers: { appeared: peersNew.slice(0, 40), gone: peersGone.slice(0, 40) },
    advisories: { appeared: advNew, fixed: advFixed },
  };
}
