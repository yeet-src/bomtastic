"use yeet";

/* The analyst: yeet:ai with tools over the inventory, live tracing,
 * and scan history — as a conversation.
 *
 * The model never sees the whole inventory. It sees counts and the
 * deterministic findings, and pulls detail through tools whose
 * handlers run here, next to the data: process detail, network,
 * pending advisories, what changed since the last scan, and two BPF
 * traces it can run for a few seconds when a snapshot is not enough.
 * What crosses the wire to the provider is what the model asked for.
 *
 * The transcript is shared state (analyst-state.js) that the page
 * renders; `ask` appends a user turn and streams the assistant's reply
 * into the last turn as it arrives.
 */
import { AiError, runTool, stream, tool } from "yeet:ai";

import { aiError, appendTurn, patchLast, resetConversation, setAiError, setThinking, thinking, turns } from "@/lib/analyst-state.js";
import { inventory, scan } from "@/lib/inventory.js";
import { findSymbol, vulnerableFunctions } from "@/lib/symbols.js";
import { traceConnects, traceExecs } from "@/lib/trace.js";

const MODEL = "claude-sonnet-5";
const MAX_TURNS = 10;

const SYSTEM = `You are a senior security engineer working a Linux host with a colleague. You have a
fresh runtime inventory gathered from /proc — binaries, mapped shared libraries, listening and
outbound sockets, containers, package ownership — plus pending security advisories matched to the
packages running processes actually use, a diff against the previous scan, and two live tracers.

Tools:
- inventory_overview: counts, deterministic findings, containers. Call first in a new conversation.
- security_advisories: published fixes not installed, with CVEs, CVSS scores, and the pids running
  the affected package. A fix that exists but is not installed on a network-facing process is the
  most important finding on any host.
- what_changed: the diff since the previous scan — new or exited processes, new binaries, changed
  hashes, listeners and peers that appeared or vanished, advisories that appeared or were fixed.
- list_processes, process_detail, network, unpackaged_files: the inventory in detail.
- trace_execs(seconds, filter): every execve on the host for up to 20 seconds. Use it to see what a
  process spawns or whether a box is quiet. Ask for 5-10 seconds unless told otherwise.
- find_symbol(pattern): which mapped binaries and libraries define a function, and the pids that
  have them in memory. Use it when an advisory or CVE names a function: "is SSL_select_next_proto
  actually loaded anywhere" is a better finding than "openssl is installed".
- vulnerable_functions: every function a pending advisory names in its text, checked against the
  symbol tables of everything in memory. The rows with hits are the advisories that matter most.
- trace_connects(seconds, pid, filter): every outbound TCP connect for up to 20 seconds, attributed
  to the connecting pid. Use it to see who a process talks to right now, not who it talked to once.

When asked for a brief, write three sections in markdown: ## Summary (two or three sentences: what
the host is, the single most important thing), ## Findings (ranked; one line naming pids, paths,
CVEs and versions, one line on why it matters or why it is benign here — a developer's toolchain is
not a dropped payload), ## Recommended actions (three to five concrete commands, most valuable
first). Otherwise answer the question asked, concisely, in markdown, citing pids, ports, paths and
package versions. Run a trace when a question is about current behaviour. Never invent a finding
the data does not support; say when the data cannot answer.`;

const inv = () => inventory() ?? { counts: {}, findings: [], processes: [], binaries: [], libraries: [], listeners: [], outbound: [], containers: [] };

/* ---- tools --------------------------------------------------------- */

const overview = tool({
  name: "inventory_overview",
  description: "Counts and the precomputed findings for the current inventory, and what changed since the previous scan in one line. Call this first in a new conversation.",
  parameters: { type: "object", properties: {} },
  handler: async () => {
    const i = inv();
    return {
      scanned_at: i.startedAt,
      counts: i.counts,
      findings: i.findings.map(({ severity, kind, title, detail, pids }) => ({ severity, kind, title, detail: detail.slice(0, 600), pids: pids.slice(0, 20) })),
      containers: i.containers.map((c) => `${c.name || c.id} ${c.image} ${c.state}`),
      since_last_scan: i.changes ? `${i.changes.summary} (previous scan ${i.changes.seconds}s earlier)` : "no previous scan",
    };
  },
});

const processes = tool({
  name: "list_processes",
  description: "Running processes with a binary, optionally filtered by a substring of the command, path or pid. Returns at most 40.",
  parameters: { type: "object", properties: { filter: { type: "string", description: "Substring matched against comm, exe and cmdline; or a pid." } } },
  handler: async ({ filter = "" } = {}) => {
    const f = String(filter).toLowerCase();
    const rows = inv()
      .processes.filter((p) => !f || String(p.pid) === f || p.comm.toLowerCase().includes(f) || p.exe.toLowerCase().includes(f) || p.cmdline.toLowerCase().includes(f))
      .slice(0, 40)
      .map((p) => ({ pid: p.pid, ppid: p.ppid, uid: p.uid, comm: p.comm, exe: p.exe, container: p.container, rss_mb: Math.round(p.rss / 1048576), started: new Date(p.started * 1000).toISOString(), cmdline: p.cmdline.slice(0, 160) }));
    return { count: rows.length, processes: rows };
  },
});

const detail = tool({
  name: "process_detail",
  description: "Everything the inventory knows about one pid: binary, package, hash, cwd, container, libraries with packages, sockets, pending advisories.",
  parameters: { type: "object", properties: { pid: { type: "integer" } }, required: ["pid"] },
  handler: async ({ pid }) => {
    const i = inv();
    const p = i.processes.find((x) => x.pid === pid);
    if (!p) return { error: `no process ${pid} in the inventory` };
    const file = i.files?.[p.exe] ?? {};
    return {
      ...p,
      started: new Date(p.started * 1000).toISOString(),
      package: file.package ?? null,
      sha256: file.sha256 ?? null,
      libs: p.libs.slice(0, 60).map((l) => ({ path: l, package: i.files?.[l]?.package ?? null })),
      libs_total: p.libs.length,
      listeners: i.listeners.filter((l) => l.pid === pid).map((l) => `${l.proto} ${l.local}`),
      outbound: i.outbound.filter((c) => c.pid === pid).map((c) => c.remote),
      advisories: (i.vulns?.advisories ?? []).filter((a) => a.processes?.some((x) => x.pid === pid)).map((a) => `${a.id} ${a.severity} ${a.cves.map((c) => c.id).join(",")}`),
    };
  },
});

const network = tool({
  name: "network",
  description: "Listening sockets and outbound connections to non-private addresses from the snapshot, each attributed to its process.",
  parameters: { type: "object", properties: {} },
  handler: async () => {
    const i = inv();
    return {
      listeners: i.listeners.map((l) => ({ proto: l.proto, local: l.local, pid: l.pid, comm: l.comm, uid: l.uid, container: l.container })),
      outbound: i.outbound.slice(0, 60).map((c) => ({ remote: c.remote, pid: c.pid, comm: c.comm })),
    };
  },
});

const unpackaged = tool({
  name: "unpackaged_files",
  description: "Binaries and libraries in use that no package owns — the part a build-time SBOM cannot see.",
  parameters: { type: "object", properties: {} },
  handler: async () => {
    const i = inv();
    const pick = (rows) => rows.filter((r) => r.package === null && !r.container).slice(0, 60).map((r) => ({ path: r.path, run_by: r.comms, pids: r.pids.slice(0, 6) }));
    return { binaries: pick(i.binaries), libraries: pick(i.libraries) };
  },
});

const securityAdvisories = tool({
  name: "security_advisories",
  description: "Pending security advisories for packages that running processes use: id, severity, CVEs with CVSS scores and summaries, installed and fixed versions, and the pids running the affected package. The fix exists but is not installed.",
  parameters: { type: "object", properties: {} },
  handler: async () => {
    const v = inv().vulns ?? { source: null, advisories: [] };
    return {
      source: v.source,
      error: v.error ?? null,
      advisories: v.advisories.slice(0, 30).map((a) => ({
        id: a.id,
        severity: a.severity,
        title: a.title,
        packages: a.packages.map((p) => `${p.name} ${p.installed} → ${p.fixed ?? "?"}`),
        cves: a.cves.map((c) => ({ id: c.id, score: c.score, summary: c.summary })),
        processes: (a.processes ?? []).slice(0, 12).map((p) => `${p.comm}(${p.pid})`),
      })),
    };
  },
});

const whatChanged = tool({
  name: "what_changed",
  description: "The diff between this scan and the previous saved one: processes started and exited, binaries appeared and gone, hashes that changed, packages upgraded, listeners and outbound peers added or removed, advisories that appeared or were fixed.",
  parameters: { type: "object", properties: {} },
  handler: async () => inv().changes ?? { error: "no previous scan to compare against — this is the first scan saved on this host" },
});

const execTrace = tool({
  name: "trace_execs",
  description: "Live: record every execve on the host for `seconds` (1-20, default 5). Optional `filter` matches command name, path, pid or parent pid. Returns the events and a summary by command and parent.",
  parameters: { type: "object", properties: { seconds: { type: "integer" }, filter: { type: "string" } } },
  handler: async (args) => {
    const r = await traceExecs(args ?? {});
    return { ...r, rows: r.rows.slice(0, 60) };
  },
});

const connectTrace = tool({
  name: "trace_connects",
  description: "Live: record every outbound TCP connect on the host for `seconds` (1-20, default 5), attributed to the connecting pid. Optional `pid` restricts to one process; `filter` matches command or remote address. Set `inbound` true to also see accepted connections (pid attribution is unreliable for those).",
  parameters: { type: "object", properties: { seconds: { type: "integer" }, pid: { type: "integer" }, filter: { type: "string" }, inbound: { type: "boolean" } } },
  handler: async (args) => {
    const r = await traceConnects(args ?? {});
    return { ...r, rows: r.rows.slice(0, 60) };
  },
});

const symbolSearch = tool({
  name: "find_symbol",
  description: "Search every binary and shared library a live host process maps for a function symbol, via ELF symbol tables. `pattern` is an exact function name or a regex. Returns the files that define it, their package and pending advisory ids, the matching symbols with addresses, and the pids/commands that have the file in memory.",
  parameters: { type: "object", properties: { pattern: { type: "string", description: "Function name (exact) or a regular expression." } }, required: ["pattern"] },
  handler: async ({ pattern }) => {
    const r = await findSymbol(pattern);
    return { ...r, hits: r.hits.slice(0, 30).map((h) => ({ ...h, symbols: h.symbols.slice(0, 6).map((s) => s.name), pids: h.pids.slice(0, 20) })) };
  },
});

const vulnFunctions = tool({
  name: "vulnerable_functions",
  description: "For every pending advisory, the functions its CVE text names, and whether each is defined in a binary or library some live process maps (via ELF symbol tables). Rows with hits name the files and the pids that have them in memory; empty hits mean the function is in no mapped file on this host.",
  parameters: { type: "object", properties: {} },
  handler: async () => {
    const r = await vulnerableFunctions();
    return { ...r, rows: r.rows.map((x) => ({ ...x, hits: x.hits.map((h) => ({ path: h.path, package: h.package, pids: h.pids.slice(0, 20), comms: h.comms.slice(0, 20) })) })) };
  },
});

const tools = [overview, securityAdvisories, whatChanged, processes, detail, network, unpackaged, vulnFunctions, symbolSearch, execTrace, connectTrace];

/* ---- the conversation ---------------------------------------------- */

let messages = []; // the provider-shaped transcript
let cancelled = false;
let current = null; // the running stream, for cancel()

/** Ask the analyst something. Streams into the shared transcript; resolves when the reply is complete. */
export async function ask(question) {
  const q = String(question ?? "").trim();
  if (!q) return { ok: false, error: "empty question" };
  if (thinking()) return { ok: false, error: "the analyst is still answering" };
  if (!inventory()) await scan();
  if (!inventory()) return { ok: false, error: "no inventory to analyse" };

  setAiError("");
  setThinking(true);
  cancelled = false;
  appendTurn({ role: "user", text: q, at: Date.now() });
  appendTurn({ role: "assistant", text: "", tools: [], at: Date.now(), done: false });
  messages.push({ role: "user", content: messages.length === 0 ? `${q}\n\n(The inventory was taken at ${inventory().startedAt}. Start with inventory_overview.)` : q });

  try {
    for (let turn = 0; turn < MAX_TURNS && !cancelled; turn++) {
      const chat = stream({ model: MODEL, system: SYSTEM, messages, tools, max_tokens: 2500, temperature: 0.2 });
      current = chat;
      let text = "";
      for await (const event of chat) {
        if (cancelled) {
          await chat.cancel().catch(() => {});
          break;
        }
        if (event.type === "text" && event.delta) {
          text += event.delta;
          patchLast((t) => (t.text += event.delta));
        }
      }
      if (cancelled) break;
      const { tool_calls = [] } = await chat.result;
      if (tool_calls.length === 0) {
        if (text.trim()) messages.push({ role: "assistant", content: text });
        break;
      }
      /* A tool-only turn adds no assistant text: a placeholder would be imitated later. */
      if (text.trim()) messages.push({ role: "assistant", content: text });
      for (const call of tool_calls) {
        const t0 = Date.now();
        patchLast((t) => (t.tools = [...t.tools, { name: call.name, args: call.arguments ?? {}, ms: null }]));
        const outcome = await runTool(tools, call);
        const ms = Date.now() - t0;
        patchLast((t) => (t.tools = t.tools.map((x, i) => (i === t.tools.length - 1 ? { ...x, ms } : x))));
        messages.push({ role: "user", content: JSON.stringify(outcome) });
      }
      if (text.trim()) patchLast((t) => (t.text += "\n\n"));
    }
    return { ok: true };
  } catch (error) {
    const code = error?.code ?? null;
    const detailText = error?.message && error.message !== code ? error.message : "";
    const message =
      code === "AI_NOT_AVAILABLE"
        ? "AI is not enabled for this account (yeet whoami)."
        : `the AI platform returned ${code ?? (error instanceof AiError ? "an error with no code" : error?.name ?? "an error")}${detailText ? `: ${detailText}` : ""}`;
    setAiError(message);
    /* Keep the transcript consistent: the provider never saw a reply. */
    if (messages[messages.length - 1]?.role === "assistant") messages.pop();
    return { ok: false, error: message };
  } finally {
    current = null;
    patchLast((t) => (t.done = true));
    setThinking(false);
  }
}

/** The standard brief, as a fresh conversation. */
export async function writeBrief() {
  await reset();
  return ask("Write the brief for this host.");
}

/** Stop the reply in flight. */
export async function cancel() {
  cancelled = true;
  await current?.cancel?.().catch(() => {});
  return { ok: true };
}

/** Forget the conversation. */
export async function reset() {
  if (thinking()) await cancel();
  messages = [];
  resetConversation();
  return { ok: true };
}

/** The current inventory, for the HTTP export route. */
export async function latest() {
  if (!inventory()) await scan();
  return inventory();
}

/** A rescan, callable from anywhere; returns counts and the diff. */
export async function rescan() {
  await scan();
  const i = inventory();
  return i ? { scannedAt: i.startedAt, counts: i.counts, changes: i.changes?.summary ?? null } : null;
}

/** The transcript, for anything outside the page that wants to read it. */
export async function transcript() {
  return { turns: turns(), thinking: thinking(), error: aiError() };
}
