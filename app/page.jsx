/* The inventory page. Runs in the isolate; every table below is read
 * straight off the shared scan, and the analyst's answer is patched in
 * as the model produces it.
 */
import { Index, Link, Show, createSignal } from "yeetkit";

import { marked } from "marked";

import { writeBrief } from "@/lib/analyst.js";
import { aiError, thinking, turns } from "@/lib/analyst-state.js";
import ChatBox from "@/lib/ChatBox.jsx";
import SymbolSearch from "@/lib/SymbolSearch.jsx";
import { fleetLoading, fleetResult, fleetSummary, loadFleet } from "@/lib/fleet-state.js";
import { inventory, progress, scan, scanError, scanning } from "@/lib/inventory.js";
import { ADVISORY, Empty, LEVEL, Pid, SEVERITY, Section, Table, ago } from "@/lib/ui.jsx";

const SHOW = 25;




export default function Home() {
  if (!inventory() && !scanning()) scan();
  if (!fleetResult() && !fleetLoading()) loadFleet();

  /* Markdown from the model, parsed whole on each delta and bound as one
   * innerHTML — a per-line render would freeze each line at the chunk it
   * arrived in. Script tags and inline handlers are stripped. */
  const html = (text) =>
    marked
      .parse(text ?? "", { gfm: true, breaks: false, async: false })
      .replace(/<script[\s\S]*?<\/script>/gi, "")
      .replace(/\son\w+="[^"]*"/gi, "");
  const [showAllBins, setShowAllBins] = createSignal(false);
  const [showAllLibs, setShowAllLibs] = createSignal(false);

  const scannedAt = () => {
    const s = inventory()?.startedAt;
    return s ? s.replace("T", " ").slice(0, 19) + " UTC" : "";
  };

  return (
    <div class="space-y-8">
      {/* ---- header ---- */}
      <section class="flex flex-wrap items-end justify-between gap-6">
        <div class="max-w-2xl space-y-2">
          <h1 class="text-2xl font-semibold tracking-tight">What is actually running</h1>
          <p class="text-muted">
            A bill of materials built from <span class="mono">/proc</span>, not from the build. Every binary and
            shared library mapped by a live process, who runs it, which package owns it, and what it is listening on
            or talking to.
          </p>
        </div>
        <div class="flex flex-col items-end gap-2">
          <button class="btn" disabled={scanning()} onClick={() => scan()}>
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M21 12a9 9 0 11-3-6.7M21 4v5h-5" />
            </svg>
            {scanning() ? "Scanning…" : "Rescan"}
          </button>
          <div class="text-xs text-faint">
            {scanning() ? progress() : inventory() ? `Scanned ${scannedAt()} in ${(inventory().timings.total / 1000).toFixed(1)}s` : ""}
          </div>
        </div>
      </section>

      {/* ---- fleet strip: the other machines, one line ---- */}
      <Show when={fleetSummary()}>
        <Link href="/fleet" class={`card flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-3 hover:bg-bg ${LEVEL[fleetSummary().level].ring}`}>
          <span class={`h-2.5 w-2.5 rounded-full ${LEVEL[fleetSummary().level].dot}`} />
          <span class="text-xs font-semibold uppercase tracking-wide text-muted">Fleet</span>
          <span class="tabular-nums">
            {fleetSummary().total} {fleetSummary().total === 1 ? "node" : "nodes"}
          </span>
          <Show when={fleetSummary().red}>
            <span class="text-high tabular-nums">{fleetSummary().red} red</span>
          </Show>
          <Show when={fleetSummary().amber}>
            <span class="text-medium tabular-nums">{fleetSummary().amber} amber</span>
          </Show>
          <Show when={fleetSummary().green}>
            <span class="text-ok tabular-nums">{fleetSummary().green} green</span>
          </Show>
          <Show when={fleetSummary().grey}>
            <span class="text-muted tabular-nums">{fleetSummary().grey} unreachable</span>
          </Show>
          <Show when={fleetSummary().pending}>
            <span class="text-faint tabular-nums">{fleetSummary().pending} waiting</span>
          </Show>
          <Show when={fleetSummary().worst}>
            <span class="text-muted">
              worst: <span class="text-fg">{fleetSummary().worst.host?.hostname ?? fleetSummary().worst.name}</span>, {fleetSummary().worst.verdict.text}
            </span>
          </Show>
          <span class="ml-auto text-xs text-accent">view fleet →</span>
        </Link>
      </Show>

      <Show when={scanError()}>
        <div class="card border-high/30 bg-high-soft px-4 py-3 text-high">Scan failed: {scanError()}</div>
      </Show>
      <Show when={inventory()?.enrichError}>
        <div class="card border-medium/30 bg-medium-soft px-4 py-3 text-medium">
          Package lookup failed: {inventory().enrichError}
        </div>
      </Show>

      <Show when={inventory()?.changes}>
        <div class={`card flex flex-wrap items-baseline gap-x-4 gap-y-1 px-4 py-3 ${inventory().changes.quiet ? "" : "border-accent/40"}`}>
          <span class="text-xs font-semibold uppercase tracking-wide text-muted">Since last scan</span>
          <span class="text-xs text-faint">{ago(inventory().changes.seconds)} ago</span>
          <span class={inventory().changes.quiet ? "text-muted" : "text-fg"}>{inventory().changes.summary}</span>
          <Show when={!inventory().changes.quiet}>
            <span class="ml-auto text-xs text-faint">
              <Index each={inventory().changes.processes.started.slice(0, 6)}>{(p) => <span class="mono mr-2">+{p().comm}</span>}</Index>
              <Index each={inventory().changes.processes.exited.slice(0, 6)}>{(p) => <span class="mono mr-2 line-through">{p().comm}</span>}</Index>
              <Index each={inventory().changes.listeners.opened}>{(l) => <span class="mono mr-2 text-ok">+{l().key}</span>}</Index>
              <Index each={inventory().changes.listeners.closed}>{(l) => <span class="mono mr-2 text-medium">−{l().key}</span>}</Index>
              <Index each={inventory().changes.advisories.appeared}>{(a) => <span class="mono mr-2 text-high">+{a().id}</span>}</Index>
              <Index each={inventory().changes.advisories.fixed}>{(a) => <span class="mono mr-2 text-ok">✓{a().id}</span>}</Index>
            </span>
          </Show>
        </div>
      </Show>

      <Show when={inventory()}>
        {/* ---- tiles ---- */}
        <section class="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-8">
          {[
            ["processes", "Processes", ""],
            ["binaries", "Binaries", ""],
            ["libraries", "Libraries", ""],
            ["unpackaged", "Unpackaged", "text-medium"],
            ["listeners", "Listening", ""],
            ["advisories", "Advisories", "text-high"],
            ["containers", "Containers", ""],
            ["high", "High findings", "text-high"],
          ].map(([key, label, color]) => (
            <div class="card px-4 py-3">
              <div class={`text-2xl font-semibold tabular-nums ${inventory().counts[key] ? color : ""}`}>
                {() => inventory().counts[key]}
              </div>
              <div class="text-xs text-muted">{label}</div>
            </div>
          ))}
        </section>

        {/* ---- findings ---- */}
        <Section title="Findings" subtitle="Deterministic, with the processes that produced each one">
          <Show when={inventory().findings.length} fallback={<Empty>No findings. Nothing on this host looks out of place.</Empty>}>
            <div class="divide-y divide-border">
              <Index each={inventory().findings}>
                {(f) => (
                  <div class="flex gap-4 px-5 py-4">
                    <div class={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${SEVERITY[f().severity].bar}`} />
                    <div class="min-w-0 flex-1 space-y-1.5">
                      <div class="flex flex-wrap items-center gap-2">
                        <span class={`badge ${SEVERITY[f().severity].badge}`}>{f().severity}</span>
                        <span class="font-medium">{f().title}</span>
                        <span class="mono text-faint">{f().kind}</span>
                      </div>
                      <p class="text-muted">{f().detail}</p>
                      <div class="flex flex-wrap items-center gap-1.5">
                        <Index each={f().pids.slice(0, 16)}>
                          {(pid) => (
                            <Link
                              href={`/proc/${pid()}`}
                              class="mono rounded-md bg-accent-soft px-1.5 py-0.5 text-accent hover:bg-accent-strong hover:text-white"
                            >
                              {pid()}
                            </Link>
                          )}
                        </Index>
                        <Show when={f().pids.length > 16}>
                          <span class="text-xs text-faint">+{f().pids.length - 16} more</span>
                        </Show>
                      </div>
                    </div>
                  </div>
                )}
              </Index>
            </div>
          </Show>
        </Section>

        {/* ---- advisories ---- */}
        <Section
          title="Security advisories"
          subtitle={
            inventory().vulns?.source === "dnf"
              ? "Published fixes not yet installed, for packages a running process maps — from the distribution's update feed, CVE detail from OSV"
              : inventory().vulns?.source === "osv"
                ? "Known vulnerabilities in packages a running process maps — from OSV"
                : "Could not check advisories on this host"
          }
        >
          <Show when={inventory().vulns?.error}>
            <div class="px-5 py-3 text-medium">{inventory().vulns.error}</div>
          </Show>
          <Show
            when={inventory().vulns?.advisories?.length}
            fallback={<Show when={!inventory().vulns?.error}><Empty>No pending security advisories for packages in use.</Empty></Show>}
          >
            <Table head={["Severity", "Advisory", "Package", "Installed → Fixed", "CVEs", "Running in"]}>
              <Index each={inventory().vulns.advisories}>
                {(a) => (
                  <tr class="align-top hover:bg-bg">
                    <td class="px-5 py-2.5">
                      <span class={`badge ${ADVISORY[a().severity?.toLowerCase()] ?? "bg-bg text-muted"}`}>{a().severity}</span>
                    </td>
                    <td class="px-5 py-2.5">
                      <a href={a().url} target="_blank" class="mono text-accent hover:underline">
                        {a().id}
                      </a>
                      <div class="max-w-xs truncate text-xs text-muted" title={a().title}>
                        {a().title}
                      </div>
                    </td>
                    <td class="px-5 py-2.5">
                      <Index each={a().packages}>{(p) => <div class="mono">{p().name}</div>}</Index>
                    </td>
                    <td class="px-5 py-2.5">
                      <Index each={a().packages}>
                        {(p) => (
                          <div class="mono text-xs">
                            <span class="text-muted">{p().installed}</span> <span class="text-faint">→</span>{" "}
                            <span class="text-ok">{p().fixed ?? "?"}</span>
                          </div>
                        )}
                      </Index>
                    </td>
                    <td class="px-5 py-2.5">
                      <Show when={a().cves.length} fallback={<span class="text-faint">not listed</span>}>
                        <Index each={a().cves}>
                          {(c) => (
                            <div class="flex items-baseline gap-2" title={c().summary ?? ""}>
                              <a href={c().url ?? `https://osv.dev/vulnerability/${c().id}`} target="_blank" class="mono text-accent hover:underline">
                                {c().id}
                              </a>
                              <Show when={c().score != null}>
                                <span class={`text-xs font-semibold tabular-nums ${c().score >= 9 ? "text-high" : c().score >= 7 ? "text-high" : c().score >= 4 ? "text-medium" : "text-muted"}`}>
                                  {c().score.toFixed(1)}
                                </span>
                              </Show>
                            </div>
                          )}
                        </Index>
                      </Show>
                    </td>
                    <td class="px-5 py-2.5">
                      <div class="flex flex-wrap gap-1">
                        <Index each={(a().processes ?? []).slice(0, 8)}>
                          {(p) => (
                            <Link href={`/proc/${p().pid}`} class="mono rounded-md bg-accent-soft px-1.5 py-0.5 text-xs text-accent hover:bg-accent-strong hover:text-white" title={String(p().pid)}>
                              {p().comm}
                            </Link>
                          )}
                        </Index>
                        <Show when={(a().processes ?? []).length > 8}>
                          <span class="text-xs text-faint">+{a().processes.length - 8}</span>
                        </Show>
                      </div>
                    </td>
                  </tr>
                )}
              </Index>
            </Table>
          </Show>
        </Section>

        <Section title="Who has this function?" subtitle="An advisory names a function; this asks the ELF symbol tables of every file a live process maps whether it is there — yeet:sym, not the package database">
          <SymbolSearch />
        </Section>

        {/* ---- analyst ---- */}
        <Section
          title="Analyst"
          subtitle="yeet:ai with tools that run on this host: the inventory, advisories, the last-scan diff, and live exec and connect traces"
          actions={
            <div class="flex items-center gap-2">
              <Show when={turns().length && !thinking()}>
                <button class="btn-secondary" onClick={() => writeBrief()}>
                  New brief
                </button>
              </Show>
              <Show when={!turns().length}>
                <button class="btn" disabled={thinking()} onClick={() => writeBrief()}>
                  Write the brief
                </button>
              </Show>
            </div>
          }
        >
          <div class="space-y-5 px-5 py-4">
            <Show when={!turns().length}>
              <p class="text-muted">
                Start with the brief, or ask a question. The model sees only counts and findings, then pulls detail through
                tools; when a question is about what a process is doing right now, it can attach a BPF trace for a few seconds.
                Nothing about this host leaves it except what the model requests.
              </p>
            </Show>

            <Index each={turns()}>
              {(t) => (
                <Show
                  when={t().role === "assistant"}
                  fallback={
                    <div class="flex justify-end">
                      <div class="max-w-2xl rounded-2xl rounded-br-md bg-accent-strong px-4 py-2 text-white">{t().text}</div>
                    </div>
                  }
                >
                  <div class="space-y-2">
                    <Show when={t().tools.length}>
                      <div class="flex flex-wrap gap-2">
                        <Index each={t().tools}>
                          {(c) => (
                            <span class="mono rounded-md border border-border bg-bg px-2 py-1 text-xs text-muted">
                              {c().name}({Object.values(c().args).join(", ").slice(0, 30)}){" "}
                              <span class="text-faint">{c().ms === null ? "…" : `${c().ms}ms`}</span>
                            </span>
                          )}
                        </Index>
                      </div>
                    </Show>
                    <Show when={t().text}>
                      <div class="brief max-w-3xl" innerHTML={html(t().text)} />
                    </Show>
                    <Show when={!t().done}>
                      <span class="pulse-dot" />
                    </Show>
                  </div>
                </Show>
              )}
            </Index>

            <Show when={aiError()}>
              <div class="rounded-lg bg-high-soft px-4 py-3 text-high">
                {aiError()}
                <span class="text-muted"> The inventory and findings above do not depend on the model.</span>
              </div>
            </Show>

            <ChatBox thinking={thinking()} />
          </div>
        </Section>

        {/* ---- listeners ---- */}
        <Section title="Listening" subtitle="Every bound socket, attributed to its process">
          <Table head={["Proto", "Address", "PID", "Process", "UID", "Binary"]}>
            <Index each={inventory().listeners}>
              {(l) => (
                <tr class="hover:bg-bg">
                  <td class="px-5 py-2 uppercase text-muted">{l().proto}</td>
                  <td class={`mono px-5 py-2 ${l().wildcard ? "text-medium" : ""}`}>{l().local}</td>
                  <td class="px-5 py-2">
                    <Pid pid={l().pid} />
                  </td>
                  <td class="px-5 py-2 font-medium">{l().comm ?? "—"}</td>
                  <td class={`px-5 py-2 tabular-nums ${l().uid === 0 ? "text-medium" : "text-muted"}`}>{l().uid}</td>
                  <td class="mono max-w-0 truncate px-5 py-2 text-muted" title={l().exe ?? ""}>
                    {l().exe ?? ""}
                  </td>
                </tr>
              )}
            </Index>
          </Table>
        </Section>

        {/* ---- outbound ---- */}
        <Show when={inventory().outbound.length}>
          <Section title="Outbound" subtitle="Established connections to non-private addresses">
            <Table head={["Remote", "PID", "Process", "Binary"]}>
              <Index each={inventory().outbound.slice(0, 40)}>
                {(c) => (
                  <tr class="hover:bg-bg">
                    <td class="mono px-5 py-2">{c().remote}</td>
                    <td class="px-5 py-2">
                      <Pid pid={c().pid} />
                    </td>
                    <td class="px-5 py-2 font-medium">{c().comm ?? "—"}</td>
                    <td class="mono max-w-0 truncate px-5 py-2 text-muted" title={c().exe ?? ""}>
                      {c().exe ?? ""}
                    </td>
                  </tr>
                )}
              </Index>
            </Table>
          </Section>
        </Show>

        {/* ---- containers ---- */}
        <Show when={inventory().containers.length}>
          <Section title="Containers" subtitle="With the host-side processes that belong to each">
            <Table head={["ID", "Name", "Image", "State", "Processes"]}>
              <Index each={inventory().containers}>
                {(c) => (
                  <tr class="hover:bg-bg">
                    <td class="mono px-5 py-2 text-muted">{c().id}</td>
                    <td class="px-5 py-2 font-medium">{c().name}</td>
                    <td class="mono max-w-0 truncate px-5 py-2 text-muted" title={c().image}>
                      {c().image}
                    </td>
                    <td class="px-5 py-2">
                      <span class={`badge ${c().state === "RUNNING" ? "bg-ok-soft text-ok" : "bg-bg text-muted"}`}>{c().state}</span>
                    </td>
                    <td class="px-5 py-2 tabular-nums">{() => inventory().processes.filter((p) => p.container === c().id).length}</td>
                  </tr>
                )}
              </Index>
            </Table>
          </Section>
        </Show>

        {/* ---- binaries ---- */}
        <BomTable
          title="Binaries"
          subtitle="One row per distinct executable"
          rows={() => (showAllBins() ? inventory().binaries : inventory().binaries.slice(0, SHOW))}
          total={() => inventory().binaries.length}
          expanded={showAllBins}
          toggle={() => setShowAllBins(!showAllBins())}
          hash
        />

        {/* ---- libraries ---- */}
        <BomTable
          title="Shared libraries"
          subtitle="One row per distinct mapped .so"
          rows={() => (showAllLibs() ? inventory().libraries : inventory().libraries.slice(0, SHOW))}
          total={() => inventory().libraries.length}
          expanded={showAllLibs}
          toggle={() => setShowAllLibs(!showAllLibs())}
        />
      </Show>
    </div>
  );
}

/* ---- pieces -------------------------------------------------------- */





function BomTable(props) {
  return (
    <Section
      title={props.title}
      subtitle={props.subtitle}
      actions={
        <Show when={props.total() > SHOW}>
          <button class="btn-secondary" onClick={props.toggle}>
            {props.expanded() ? `Show ${SHOW}` : `Show all ${props.total()}`}
          </button>
        </Show>
      }
    >
      <div class="overflow-x-auto">
        <table class="w-full text-left">
          <thead>
            <tr class="table-head border-b border-border bg-bg/60">
              <th class="px-5 py-2 font-semibold">Path</th>
              <th class="px-5 py-2 font-semibold">Package</th>
              {props.hash && <th class="px-5 py-2 font-semibold">SHA-256</th>}
              <th class="px-5 py-2 text-right font-semibold">Procs</th>
              <th class="px-5 py-2 font-semibold">Run by</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-border">
            <Index each={props.rows()}>
              {(r) => (
                <tr class="hover:bg-bg">
                  <td class="mono max-w-md truncate px-5 py-2" title={r().path}>
                    {r().path}
                  </td>
                  <td class="px-5 py-2">
                    {r().package ? (
                      <span class="mono text-muted">{r().package}</span>
                    ) : r().container ? (
                      <span class="badge bg-bg text-muted">container {r().container}</span>
                    ) : (
                      <span class="badge bg-medium-soft text-medium">unpackaged</span>
                    )}
                  </td>
                  {props.hash && (
                    <td class="mono px-5 py-2 text-faint" title={r().sha256 ?? ""}>
                      {r().sha256 ? r().sha256.slice(0, 12) : ""}
                    </td>
                  )}
                  <td class="px-5 py-2 text-right tabular-nums">{r().pids.length}</td>
                  <td class="max-w-xs truncate px-5 py-2 text-muted" title={r().comms.join(" ")}>
                    {r().comms.slice(0, 4).join(", ")}
                  </td>
                </tr>
              )}
            </Index>
          </tbody>
        </table>
      </div>
    </Section>
  );
}
