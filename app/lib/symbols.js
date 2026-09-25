"use yeet";

/* Who has this function? The inventory says which processes map which
 * files; `yeet:sym`'s Inspector says which functions a file defines.
 * Together they answer the question an advisory actually raises: is
 * the named function present in a library some live process has
 * mapped right now — not "is the package installed".
 *
 * Inspectors are opened once per path and cached for the life of an
 * inventory; opening a distro libssl is ~10ms, so a full pass over
 * every mapped file on a host is a few seconds the first time and
 * near-instant after.
 */
import { Inspector } from "yeet:sym";

import { inventory } from "@/lib/inventory.js";

const CONCURRENCY = 16;
const MAX_HITS_PER_FILE = 25;

let cache = new Map(); // path → Promise<Inspector | null>
let cacheFor = null; // inventory().startedAt the cache was built for

function inspector(path) {
  let p = cache.get(path);
  if (!p) {
    p = Inspector.open(path).catch(() => null); // not an ELF, unreadable, gone
    cache.set(path, p);
  }
  return p;
}

/* A bare identifier matches exactly; anything else is a regex. */
function compile(pattern) {
  const text = String(pattern ?? "").trim();
  if (!text) throw new Error("give a function name or a regex");
  if (/^[A-Za-z_][A-Za-z0-9_.@]*$/.test(text)) return { regex: new RegExp(`^${text.replace(/[.@]/g, "\\$&")}$`), exact: true };
  return { regex: new RegExp(text), exact: false };
}

/* path → who maps it, for the host's processes. Container paths resolve
 * against another root, so the host-side Inspector would open the wrong
 * file: skip them. */
function usersOf(inv) {
  const users = new Map();
  for (const p of inv.processes) {
    if (p.container) continue;
    for (const path of [p.exe, ...p.libs]) {
      let u = users.get(path);
      if (!u) users.set(path, (u = { pids: new Set(), comms: new Set(), procs: [] }));
      u.pids.add(p.pid);
      u.comms.add(p.comm);
      u.procs.push({ pid: p.pid, comm: p.comm });
    }
  }
  return users;
}

async function search(inv, regex, users = usersOf(inv)) {
  if (cacheFor !== inv.startedAt) { cache = new Map(); cacheFor = inv.startedAt; }
  const paths = [...users.keys()];
  const hits = [];
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(CONCURRENCY, paths.length) }, async () => {
      while (i < paths.length) {
        const path = paths[i++];
        const insp = await inspector(path);
        if (!insp) continue;
        let found;
        try {
          found = await insp.find(regex);
        } catch {
          continue;
        }
        if (!found.length) continue;
        const u = users.get(path);
        const pkg = inv.files?.[path]?.package ?? null;
        hits.push({
          path,
          package: pkg,
          advisories: pkg ? (inv.vulns?.byPackage?.[pkg.split(" ")[0]] ?? []) : [],
          symbols: found.slice(0, MAX_HITS_PER_FILE).map((s) => ({ name: s.demangled ?? s.name, addr: `0x${s.addr.toString(16)}`, size: s.size, kind: s.kind })),
          more: Math.max(0, found.length - MAX_HITS_PER_FILE),
          pids: [...u.pids].sort((a, b) => a - b),
          comms: [...u.comms].sort(),
          procs: [...u.procs].sort((a, b) => a.pid - b.pid),
        });
      }
    }),
  );
  hits.sort((a, b) => b.advisories.length - a.advisories.length || b.pids.length - a.pids.length || a.path.localeCompare(b.path));
  return { files_searched: paths.length, hits };
}

/**
 * Search every binary and shared library a host process maps for a symbol.
 * @param {string} pattern  function name (exact) or a regex
 */
export async function findSymbol(pattern) {
  const inv = inventory();
  if (!inv) throw new Error("no inventory yet — scan first");
  const { regex } = compile(pattern);
  const t0 = Date.now();
  const { files_searched, hits } = await search(inv, regex);
  return {
    pattern: String(pattern).trim(),
    files_searched,
    files_with_symbol: hits.length,
    processes: new Set(hits.flatMap((h) => h.pids)).size,
    ms: Date.now() - t0,
    hits,
  };
}

/* Function names an advisory text mentions: `foo_bar`, `Foo::bar`,
 * `baz()`. Lower-cased identifiers that are really Python attributes
 * (`get_data`) will simply not be found in any ELF, which the list
 * shows as "not in memory". */
const IDENT = /\b[A-Za-z_][A-Za-z0-9]*_[A-Za-z0-9_]+\b|\b([A-Za-z_][A-Za-z0-9_]*)\(\)/g;
const NOISE = /^(e\.g|i\.e|x86_64|aarch64|use_after|out_of|null_pointer|CVE_|ID_|http_|https_)/i;

function namedFunctions(text) {
  const out = new Set();
  for (const m of String(text ?? "").matchAll(IDENT)) {
    const name = (m[1] ?? m[0]).replace(/\(\)$/, "");
    if (name.length >= 5 && !NOISE.test(name) && !/^\d/.test(name)) out.add(name);
  }
  return [...out];
}

let listCache = null; // { for: startedAt, rows }

/**
 * The automatic list: every function a pending advisory names, checked
 * against the symbol tables of everything in memory. One row per
 * (advisory, CVE, function); `hits` empty means the name is in no mapped
 * file on this host.
 */
export async function vulnerableFunctions() {
  const inv = inventory();
  if (!inv) throw new Error("no inventory yet — scan first");
  if (listCache?.for === inv.startedAt) return listCache.rows;
  const t0 = Date.now();
  const users = usersOf(inv);
  const rows = [];
  for (const a of inv.vulns?.advisories ?? []) {
    /* dnf advisories carry CVE entries with summaries; OSV ones (Debian)
     * have no CVE entries and the text is the advisory title. */
    const entries = a.cves.length ? a.cves : [{ id: a.id, summary: a.title, url: a.url, score: null }];
    for (const c of entries) {
      for (const fn of namedFunctions(`${a.title ?? ""} ${c.summary ?? ""} ${c.details ?? ""}`)) {
        const regex = new RegExp(`^${fn.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "i");
        const { hits } = await search(inv, regex, users);
        rows.push({
          advisory: a.id,
          severity: a.severity,
          url: a.url,
          cve: c.id,
          cve_url: c.url ?? `https://osv.dev/vulnerability/${c.id}`,
          score: c.score ?? null,
          packages: a.packages.map((p) => p.name),
          function: fn,
          /* A name from a Python advisory can collide with a C symbol in an
           * unrelated library; keep the hit but say which package it is in. */
          hits: hits
            .map((h) => ({ path: h.path, package: h.package, same_package: a.packages.some((p) => h.package?.startsWith(`${p.name} `)), pids: h.pids, comms: h.comms, procs: h.procs, symbols: h.symbols.slice(0, 4) }))
            .sort((x, y) => y.same_package - x.same_package),
        });
      }
    }
  }
  const rank = (r) => (r.hits.some((h) => h.same_package) ? 2 : r.hits.length ? 1 : 0);
  rows.sort((x, y) => rank(y) - rank(x) || (y.score ?? 0) - (x.score ?? 0));
  const result = { scanned_at: inv.startedAt, ms: Date.now() - t0, rows };
  listCache = { for: inv.startedAt, rows: result };
  return result;
}
