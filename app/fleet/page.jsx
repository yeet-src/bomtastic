/* The fleet page: one row per machine, the same verdict colours as the
 * inventory. Runs in the isolate like every page; the walk itself is a
 * `"use server"` call, because the gateway's manifest is HTTP and the
 * nodes are dialed over ws — both are Node's to do. */
import { Index, Link, Show } from "yeetkit";

import { fleetLoading, fleetResult, loadFleet } from "@/lib/fleet-state.js";
import { ADVISORY, LEVEL, since } from "@/lib/ui.jsx";

export default function Fleet() {
  if (!fleetResult() && !fleetLoading()) loadFleet();

  const totals = () => {
    const nodes = fleetResult()?.nodes ?? [];
    const by = (level) => nodes.filter((n) => n.verdict.level === level).length;
    return { nodes: nodes.length, red: by("red"), amber: by("amber"), green: by("green"), grey: by("grey"), pending: by("pending") };
  };

  return (
    <div class="space-y-8">
      <section class="flex flex-wrap items-end justify-between gap-6">
        <div class="max-w-2xl space-y-2">
          <h1 class="text-2xl font-semibold tracking-tight">Fleet</h1>
          <p class="text-muted">
            Every machine whose bomtastic this gateway can reach. A node is a route in the gateway's manifest; its row is
            one call to the isolate behind that route, relayed by each gateway between here and there.
          </p>
        </div>
        <div class="flex flex-col items-end gap-2">
          <button class="btn" disabled={fleetLoading()} onClick={() => loadFleet({ force: true })}>
            {fleetLoading() ? "Asking every node…" : "Refresh"}
          </button>
          <div class="text-xs text-faint">gateway {fleetResult()?.gateway ?? "…"}</div>
        </div>
      </section>

      <Show when={fleetResult()?.error}>
        <div class="card border-high/30 bg-high-soft px-4 py-3 text-high">{fleetResult().error}</div>
      </Show>

      <Show when={fleetResult() && !fleetResult().error}>
        <section class="grid grid-cols-3 gap-3 sm:grid-cols-6">
          {[
            ["nodes", "Nodes", ""],
            ["red", "Red", "text-high"],
            ["amber", "Amber", "text-medium"],
            ["green", "Green", "text-ok"],
            ["grey", "Unreachable", "text-muted"],
            ["pending", "Waiting", "text-faint"],
          ].map(([key, label, color]) => (
            <div class="card px-4 py-3">
              <div class={`text-2xl font-semibold tabular-nums ${totals()[key] ? color : ""}`}>{() => totals()[key]}</div>
              <div class="text-xs text-muted">{label}</div>
            </div>
          ))}
        </section>

        <div class="space-y-3">
          <Index each={fleetResult().nodes}>
            {(n) => (
              <div class={`card px-5 py-4 ${LEVEL[n().verdict.level].ring}`}>
                <div class="flex flex-wrap items-center gap-3">
                  <span class={`h-2.5 w-2.5 rounded-full ${LEVEL[n().verdict.level].dot}`} />
                  <Link href={n().local ? "/" : `/fleet/${n().slug}`} class="font-medium hover:underline">
                    {n().host?.hostname ?? n().name}
                  </Link>
                  <span class="mono text-xs text-faint">{n().path}</span>
                  <Show when={n().host?.platform}>
                    <span class="text-xs text-muted">{n().host.platform}</span>
                  </Show>
                  <span class={`badge ${LEVEL[n().verdict.level].badge}`}>{n().verdict.level}</span>
                  <span class="text-muted">{n().verdict.text}</span>
                  <span class="ml-auto text-xs text-faint">
                    {n().hops > 1 ? `${n().hops} hops · ` : ""}
                    {n().ok ? `scanned ${since(n().startedAt)} · ${(n().ms / 1000).toFixed(1)}s` : n().pending ? "waiting for the node…" : n().error}
                  </span>
                </div>
                <Show when={n().ok}>
                  <div class="mt-3 grid grid-cols-3 gap-3 text-sm sm:grid-cols-6">
                    {[
                      ["processes", "processes"],
                      ["listeners", "listening"],
                      ["outbound", "outbound"],
                      ["containers", "containers"],
                      ["unpackaged", "unpackaged"],
                      ["advisories", "advisories"],
                    ].map(([key, label]) => (
                      <div>
                        <span class="tabular-nums font-medium">{() => n().counts[key]}</span>{" "}
                        <span class="text-muted">{label}</span>
                      </div>
                    ))}
                  </div>
                  <div class="mt-3 flex flex-wrap items-center gap-2 text-xs">
                    <Index each={n().top}>
                      {(a) => (
                        <span class={`badge ${ADVISORY[a().severity?.toLowerCase()] ?? "bg-bg text-muted"}`}>
                          {a().id} · {a().packages.join(", ")}
                        </span>
                      )}
                    </Index>
                    <Index each={n().highFindings}>{(t) => <span class="badge bg-high-soft text-high">{t()}</span>}</Index>
                    <Show when={n().changes}>
                      <span class="text-faint">since last scan: {n().changes}</span>
                    </Show>
                    <span class="ml-auto flex items-center gap-3">
                      <Link href={n().local ? "/" : `/fleet/${n().slug}`} class="text-accent hover:underline">
                        {n().local ? "inventory →" : "details →"}
                      </Link>
                      <Show when={n().ui}>
                        <a href={n().ui} target="_blank" class="text-muted hover:text-fg hover:underline">
                          open on the node ↗
                        </a>
                      </Show>
                    </span>
                  </div>
                </Show>
              </div>
            )}
          </Index>
          <Show when={fleetResult().nodes.length === 0}>
            <div class="card px-5 py-6 text-center text-muted">
              The gateway lists no <span class="mono">/app</span> routes. Import the service on this machine and add a{" "}
              <span class="mono">--node host:port</span> per peer.
            </div>
          </Show>
        </div>
      </Show>
    </div>
  );
}
