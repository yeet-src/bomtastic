"use server";

/* Pending security advisories for the packages that are actually
 * running. Node's job, because it needs the package manager and the
 * network.
 *
 * Two sources, chosen by distro:
 *
 *   dnf   Fedora and the RHEL family. `dnf updateinfo --json` is the
 *         distro's own advisory feed, already filtered to installed
 *         packages with a pending update — and Fedora is not an OSV
 *         ecosystem, so this is the only accurate source there.
 *   OSV   Debian, Ubuntu, Alpine, and the RHEL clones by ecosystem
 *         name. Package name plus version in, advisory ids out.
 *
 * Either way the CVE ids are then looked up in OSV for a summary and
 * a CVSS vector, so the page and the model can say what a hole is and
 * how bad, not just that one exists.
 */
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";

const ADVISORY_TTL = 30 * 60 * 1000;
const CVE_TTL = 12 * 60 * 60 * 1000;
const CVE_CONCURRENCY = 6;
const CVE_LIMIT = 80;

const run = (cmd, args, timeout = 120_000) =>
  new Promise((resolve) =>
    execFile(cmd, args, { maxBuffer: 64 * 1024 * 1024, timeout }, (error, stdout, stderr) =>
      resolve({ code: error?.code ?? 0, stdout: String(stdout), stderr: String(stderr), missing: error?.code === "ENOENT" }),
    ),
  );

let cached = null; // { at, distro, source, advisories }
const cveCache = new Map(); // id -> { at, detail }

/**
 * @param {{ packages: string[] }} arg  "NAME EVR" strings for the packages in use
 * @returns {{ source, distro, advisories: Advisory[], byPackage: Record<string, string[]>, error? }}
 */
export async function advisories({ packages = [] }) {
  const installed = new Map(); // name -> evr
  for (const p of packages) {
    const sp = p.indexOf(" ");
    if (sp > 0) installed.set(p.slice(0, sp), p.slice(sp + 1));
  }

  let feed;
  try {
    feed = await pendingAdvisories(installed);
  } catch (error) {
    return { source: null, distro: await distro(), advisories: [], byPackage: {}, error: String(error?.message ?? error) };
  }

  /* Only advisories that touch a package something is running. */
  const relevant = feed.advisories
    .map((a) => ({ ...a, packages: a.packages.filter((p) => installed.has(p.name)) }))
    .filter((a) => a.packages.length > 0);

  const cveIds = [...new Set(relevant.flatMap((a) => a.cves))].slice(0, CVE_LIMIT);
  const details = await cveDetails(cveIds);
  for (const a of relevant) {
    a.cves = a.cves.map((id) => ({ id, ...(details.get(id) ?? {}) }));
    for (const p of a.packages) p.installed = installed.get(p.name);
  }

  const byPackage = {};
  for (const a of relevant) for (const p of a.packages) (byPackage[p.name] ??= []).push(a.id);

  const rank = { critical: 0, important: 1, high: 1, moderate: 2, medium: 2, low: 3 };
  relevant.sort((a, b) => (rank[a.severity?.toLowerCase()] ?? 4) - (rank[b.severity?.toLowerCase()] ?? 4) || a.id.localeCompare(b.id));

  return { source: feed.source, distro: feed.distro, advisories: relevant, byPackage };
}

/* ---- the distro's feed ------------------------------------------ */

async function distro() {
  const text = await readFile("/etc/os-release", "utf8").catch(() => "");
  const get = (k) => /^(?:k)=["']?([^"'\n]*)/m.exec(text.replace(new RegExp(`^${k}=`, "m"), "k="))?.[1] ?? null;
  return { id: get("ID"), version: get("VERSION_ID"), like: get("ID_LIKE") };
}

async function pendingAdvisories(installed) {
  if (cached && Date.now() - cached.at < ADVISORY_TTL) return cached;
  const d = await distro();

  let result;
  if (!(await run("dnf", ["--version"], 10_000)).missing) result = await fromDnf(d);
  else if (!(await run("dpkg-query", ["--version"], 10_000)).missing) result = await fromOsv(d, installed, (name, version) => ({ package: { purl: `pkg:deb/${d.id}/${name}@${version}` } }));
  else if (!(await run("apk", ["--version"], 10_000)).missing) result = await fromOsv(d, installed, (name, version) => ({ package: { name, ecosystem: `Alpine:v${d.version?.split(".").slice(0, 2).join(".")}` }, version }));
  else result = { source: null, distro: d, advisories: [] };

  cached = { at: Date.now(), ...result };
  return cached;
}

/* dnf5's JSON: one object per advisory, with the fixed packages under
 * collections.packages as NEVRAs and the CVE ids scattered through the
 * title, description and bugzilla reference titles. */
async function fromDnf(d) {
  const out = await run("dnf", ["-q", "updateinfo", "info", "--security", "--json"]);
  if (out.code !== 0 && !out.stdout.trim()) throw new Error(`dnf updateinfo failed: ${out.stderr.trim().split("\n").pop() || out.code}`);
  let json = {};
  try {
    json = JSON.parse(out.stdout || "{}");
  } catch {
    throw new Error("dnf updateinfo returned unparseable JSON");
  }

  const advisories = [];
  for (const e of Object.values(json)) {
    const blob = [e.Title, e.Description, ...(e.references ?? []).map((r) => `${r.Title ?? ""} ${r.Id ?? ""}`)].join("\n");
    const cves = [...new Set(blob.match(/CVE-\d{4}-\d{4,}/g) ?? [])];
    const packages = new Map();
    for (const nevra of e.collections?.packages ?? []) {
      const p = parseNevra(nevra);
      if (!p || p.arch === "src" || /-(debuginfo|debugsource)$/.test(p.name)) continue;
      packages.set(p.name, { name: p.name, fixed: p.evr });
    }
    advisories.push({
      id: e.Name,
      title: e.Title,
      severity: e.Severity ?? "Unknown",
      issued: e.Issued,
      description: (e.Description ?? "").trim().slice(0, 600),
      url: `https://bodhi.fedoraproject.org/updates/${e.Name}`,
      cves,
      packages: [...packages.values()],
    });
  }
  return { source: "dnf", distro: d, advisories };
}

/* name-[epoch:]version-release.arch, where name may itself contain
 * dashes: peel arch, then release, then version, from the right. */
function parseNevra(nevra) {
  const dot = nevra.lastIndexOf(".");
  if (dot < 0) return null;
  const arch = nevra.slice(dot + 1);
  const rest = nevra.slice(0, dot);
  const r = rest.lastIndexOf("-");
  if (r < 0) return null;
  const v = rest.lastIndexOf("-", r - 1);
  if (v < 0) return null;
  return { name: rest.slice(0, v), evr: rest.slice(v + 1), arch };
}

/* OSV batch query by package: the ids come back, details are fetched
 * per id below like any other CVE. */
async function fromOsv(d, installed, toQuery) {
  const names = [...installed.entries()];
  const advisories = [];
  for (let i = 0; i < names.length; i += 500) {
    const slice = names.slice(i, i + 500);
    const body = JSON.stringify({ queries: slice.map(([name, version]) => toQuery(name, version)) });
    const res = await fetch("https://api.osv.dev/v1/querybatch", { method: "POST", body, headers: { "content-type": "application/json" } });
    if (!res.ok) throw new Error(`OSV querybatch ${res.status}`);
    const { results = [] } = await res.json();
    results.forEach((r, j) => {
      const [name, version] = slice[j];
      for (const v of r.vulns ?? []) {
        advisories.push({
          id: v.id,
          title: v.id,
          severity: "Unknown",
          issued: v.modified,
          description: "",
          url: `https://osv.dev/vulnerability/${v.id}`,
          cves: /^CVE-/.test(v.id) ? [v.id] : [],
          packages: [{ name, fixed: null, installed: version }],
          osv: true,
        });
      }
    });
  }
  /* Non-CVE ids (DSA-, USN-, ALSA-) still have OSV records; fetch their
   * aliases so the CVE list is filled in. */
  const detail = await cveDetails(advisories.filter((a) => a.osv && !a.cves.length).map((a) => a.id));
  for (const a of advisories) {
    const dd = detail.get(a.id);
    if (dd) {
      a.title = dd.summary || a.id;
      a.cves = dd.aliases?.filter((x) => /^CVE-/.test(x)) ?? a.cves;
      a.severity = dd.severity ?? a.severity;
    }
  }
  return { source: "osv", distro: d, advisories };
}

/* ---- CVE details from OSV ---------------------------------------- */

async function cveDetails(ids) {
  const out = new Map();
  const todo = [];
  for (const id of ids) {
    const c = cveCache.get(id);
    if (c && Date.now() - c.at < CVE_TTL) out.set(id, c.detail);
    else todo.push(id);
  }
  let at = 0;
  await Promise.all(
    Array.from({ length: Math.min(CVE_CONCURRENCY, todo.length) }, async () => {
      while (at < todo.length) {
        const id = todo[at++];
        const detail = await fetchCve(id);
        cveCache.set(id, { at: Date.now(), detail });
        out.set(id, detail);
      }
    }),
  );
  return out;
}

async function fetchCve(id) {
  try {
    const res = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(15_000) });
    if (!res.ok) return { summary: null, vector: null, score: null, url: `https://osv.dev/vulnerability/${id}` };
    const v = await res.json();
    const vector = v.severity?.find((s) => /^CVSS_V3/.test(s.type))?.score ?? v.severity?.[0]?.score ?? null;
    const score = vector ? cvss3(vector) : null;
    return {
      summary: v.summary ?? v.details?.split("\n")[0]?.slice(0, 200) ?? null,
      vector,
      score,
      severity: score === null ? null : score >= 9 ? "Critical" : score >= 7 ? "Important" : score >= 4 ? "Moderate" : "Low",
      aliases: v.aliases ?? [],
      url: `https://osv.dev/vulnerability/${id}`,
    };
  } catch {
    return { summary: null, vector: null, score: null, url: `https://osv.dev/vulnerability/${id}` };
  }
}

/* CVSS v3.x base score from the vector string, per the specification's
 * equations. Only the base metrics are read. */
function cvss3(vector) {
  const m = Object.fromEntries(vector.split("/").slice(1).map((kv) => kv.split(":")));
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV];
  const AC = { L: 0.77, H: 0.44 }[m.AC];
  const UI = { N: 0.85, R: 0.62 }[m.UI];
  const changed = m.S === "C";
  const PR = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR];
  const cia = { H: 0.56, L: 0.22, N: 0 };
  if ([AV, AC, UI, PR].some((x) => x === undefined) || !(m.C in cia) || !(m.I in cia) || !(m.A in cia)) return null;
  const iss = 1 - (1 - cia[m.C]) * (1 - cia[m.I]) * (1 - cia[m.A]);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  const exploit = 8.22 * AV * AC * PR * UI;
  if (impact <= 0) return 0;
  const raw = changed ? Math.min(1.08 * (impact + exploit), 10) : Math.min(impact + exploit, 10);
  return Math.ceil(raw * 10) / 10;
}
