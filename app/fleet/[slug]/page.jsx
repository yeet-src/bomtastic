/* One node, seen from the hub: its findings, advisories, sockets and
 * containers, from the scan its own isolate handed over in the fleet
 * walk. Read-only — the analyst and the live traces run where the
 * processes are, so those are a link to the node's own page. */
import { Index, Link, Show } from "yeetkit";

import { fleetLoading, fleetResult, loadFleet, nodeBySlug } from "@/lib/fleet-state.js";
import { ADVISORY, Empty, LEVEL, Pid, SEVERITY, Section, Table, since } from "@/lib/ui.jsx";

export default function Node(props) {
  if (!fleetResult() && !fleetLoading()) loadFleet();
  const node = () => nodeBySlug(props.params.slug);
  const inv = () => node()?.inventory ?? null;

  return (
    <div class="space-y-8">
      <div class="flex flex-wrap items-center gap-3">
        <Link href="/fleet" class="btn-secondary">
          ← Fleet
        </Link>
        <Show when={node()} fallback={<h1 class="text-2xl font-semibold tracking-tight text-muted">{fleetLoading() ? "Asking the fleet…" : `No node ${props.params.slug} in the fleet`}</h1>}>
          <span class={`h-2.5 w-2.5 rounded-full ${LEVEL[node().verdict.level].dot}`} />
          <h1 class="text-2xl font-semibold tracking-tight">{node().host?.hostname ?? node().name}</h1>
          <span class={`badge ${LEVEL[node().verdict.level].badge}`}>{node().verdict.level}</span>
          <span class="text-muted">{node().verdict.text}</span>
          <span class="ml-auto flex items-center gap-3 text-xs text-faint">
            <Show when={node().ok}>
              <span>scanned {since(node().startedAt)}</span>
            </Show>
            <Show when={node().ui}>
              <a href={node().ui} target="_blank" class="btn-secondary">
                Open on the node ↗
              </a>
            </Show>
            <button class="btn-secondary" disabled={fleetLoading()} onClick={() => loadFleet({ force: true })}>
              {fleetLoading() ? "Refreshing…" : "Refresh"}
            </button>
          </span>
        </Show>
      </div>

      <Show when={node() && !node().ok && !node().pending}>
        <div class="card border-high/30 bg-high-soft px-4 py-3 text-high">Unreachable: {node().error}</div>
      </Show>
      <Show when={node()?.pending}>
        <div class="card px-4 py-3 text-muted">Waiting for the node to answer…</div>
      </Show>

      <Show when={inv()}>
        <div class="card grid grid-cols-2 gap-x-6 gap-y-2 px-5 py-4 text-sm sm:grid-cols-4">
          <div>
            <div class="text-xs text-muted">Route</div>
            <div class="mono">{node().path}</div>
          </div>
          <div>
            <div class="text-xs text-muted">Platform</div>
            <div>{node().host?.platform ?? "—"} {node().host?.arch ?? ""}</div>
          </div>
          <div>
            <div class="text-xs text-muted">Hops</div>
            <div class="tabular-nums">{node().hops}</div>
          </div>
          <div>
            <div class="text-xs text-muted">Since last scan there</div>
            <div class="text-muted">{inv().changes?.summary ?? "first scan"}</div>
          </div>
        </div>

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
              <div class={`text-2xl font-semibold tabular-nums ${inv().counts[key] ? color : ""}`}>{() => inv().counts[key]}</div>
              <div class="text-xs text-muted">{label}</div>
            </div>
          ))}
        </section>

        <Section title="Findings" subtitle="As the node's own scan judged them">
          <Show when={inv().findings.length} fallback={<Empty>No findings on this node.</Empty>}>
            <div class="divide-y divide-border">
              <Index each={inv().findings}>
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
                      <div class="mono text-xs text-faint">pids {f().pids.slice(0, 16).join(", ")}{f().pids.length > 16 ? ` +${f().pids.length - 16}` : ""}</div>
                    </div>
                  </div>
                )}
              </Index>
            </div>
          </Show>
        </Section>

        <Section
          title="Security advisories"
          subtitle={inv().vulns.source === "dnf" ? "From the node's distribution update feed, CVE detail from OSV" : inv().vulns.source === "osv" ? "From OSV, for packages a running process maps" : "The node could not check advisories"}
        >
          <Show when={inv().vulns.error}>
            <div class="px-5 py-3 text-medium">{inv().vulns.error}</div>
          </Show>
          <Show when={inv().vulns.advisories.length} fallback={<Show when={!inv().vulns.error}><Empty>No pending security advisories for packages in use.</Empty></Show>}>
            <Table head={["Severity", "Advisory", "Package", "Installed → Fixed", "CVEs", "Running in"]}>
              <Index each={inv().vulns.advisories}>
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
                                <span class={`text-xs font-semibold tabular-nums ${c().score >= 7 ? "text-high" : c().score >= 4 ? "text-medium" : "text-muted"}`}>{c().score.toFixed(1)}</span>
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
                            <span class="mono rounded-md bg-bg px-1.5 py-0.5 text-xs text-muted" title={String(p().pid)}>
                              {p().comm}
                            </span>
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

        <Section title="Listening" subtitle="Every bound socket on the node, attributed to its process">
          <Table head={["Proto", "Address", "PID", "Process", "UID", "Binary"]}>
            <Index each={inv().listeners}>
              {(l) => (
                <tr class="hover:bg-bg">
                  <td class="px-5 py-2 uppercase text-muted">{l().proto}</td>
                  <td class={`mono px-5 py-2 ${l().wildcard ? "text-medium" : ""}`}>{l().local}</td>
                  <td class="px-5 py-2">
                    <Pid pid={l().pid} remote />
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

        <Show when={inv().outbound.length}>
          <Section title="Outbound" subtitle="Established connections to non-private addresses">
            <Table head={["Remote", "PID", "Process", "Binary"]}>
              <Index each={inv().outbound}>
                {(c) => (
                  <tr class="hover:bg-bg">
                    <td class="mono px-5 py-2">{c().remote}</td>
                    <td class="px-5 py-2">
                      <Pid pid={c().pid} remote />
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

        <Show when={inv().containers.length}>
          <Section title="Containers" subtitle="With the host-side processes that belong to each">
            <Table head={["ID", "Name", "Image", "State", "Processes"]}>
              <Index each={inv().containers}>
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
                    <td class="px-5 py-2 tabular-nums">{() => inv().processes.filter((p) => p.container === c().id).length}</td>
                  </tr>
                )}
              </Index>
            </Table>
          </Section>
        </Show>

        <p class="text-xs text-faint">
          Binaries, shared libraries, per-process pages, the analyst and live traces stay on the node
          {node().ui ? <>: <a href={node().ui} target="_blank" class="text-accent hover:underline">{node().ui}</a></> : "."}
        </p>
      </Show>
    </div>
  );
}
