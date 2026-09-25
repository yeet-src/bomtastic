"use client";

/* "Who has this function?" — an island, so typing stays in the browser;
 * Enter makes one call to the isolate, which asks yeet:sym about every
 * file a live process maps. */
import { createSignal, onMount } from "solid-js";

import { findSymbol, vulnerableFunctions } from "@/lib/symbols.js";

const EXAMPLES = ["SSL_select_next_proto", "gets", "^png_", "kerberos|krb5"];

export default function SymbolSearch() {
  const [text, setText] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [result, setResult] = createSignal(null);
  const [error, setError] = createSignal("");
  const [list, setList] = createSignal(null);
  const [listError, setListError] = createSignal("");

  onMount(async () => {
    try {
      setList(await vulnerableFunctions());
    } catch (e) {
      setListError(String(e?.message ?? e));
    }
  });

  const run = async (q = text()) => {
    const pattern = q.trim();
    if (!pattern || busy()) return;
    setText(pattern);
    setBusy(true);
    setError("");
    try {
      setResult(await findSymbol(pattern));
    } catch (e) {
      setResult(null);
      setError(String(e?.message ?? e));
    } finally {
      setBusy(false);
    }
  };

  const Procs = (props) => {
    const max = props.max ?? 12;
    return (
      <div class="flex max-w-xs flex-wrap gap-1">
        {props.procs.slice(0, max).map((x) => (
          <a href={`/proc/${x.pid}`} class="mono rounded-md bg-accent-soft px-1.5 py-0.5 text-xs text-accent hover:bg-accent-strong hover:text-white" title={String(x.pid)}>
            {x.comm}
          </a>
        ))}
        {props.procs.length > max && <span class="text-xs text-faint">+{props.procs.length - max}</span>}
      </div>
    );
  };

  return (
    <div class="space-y-4 px-5 py-4">
      {/* ---- the automatic list: functions the advisories name ---- */}
      <div>
        <div class="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">Functions named by pending advisories</div>
        {listError() && <div class="text-xs text-high">{listError()}</div>}
        {!list() && !listError() && <div class="text-xs text-faint">Checking symbol tables…</div>}
        {list() && list().rows.length === 0 && <div class="text-xs text-muted">No pending advisory names a function in its text.</div>}
        {list() && list().rows.length > 0 && (
          <div class="overflow-x-auto rounded-lg border border-border">
            <table class="w-full text-left text-sm">
              <thead>
                <tr class="table-head border-b border-border bg-bg/60">
                  <th class="px-4 py-2 font-semibold">CVE</th>
                  <th class="px-4 py-2 font-semibold">Function</th>
                  <th class="px-4 py-2 font-semibold">Defined in</th>
                  <th class="px-4 py-2 font-semibold">In memory in</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-border">
                {list().rows.map((r) => (
                  <tr class="align-top hover:bg-bg">
                    <td class="px-4 py-2">
                      <a href={r.cve_url} target="_blank" class="mono text-accent hover:underline">{r.cve}</a>
                      <div class="text-xs text-muted">{r.packages.join(", ")}{r.score != null && <span class="ml-2 font-semibold tabular-nums">{r.score.toFixed(1)}</span>}</div>
                    </td>
                    <td class="mono px-4 py-2">{r.function}</td>
                    <td class="px-4 py-2">
                      {r.hits.length === 0 ? (
                        <span class="text-xs text-faint">not in any mapped file</span>
                      ) : (
                        r.hits.map((h) => (
                          <div class={`mono truncate text-xs ${h.same_package ? "" : "text-muted"}`} title={h.path}>
                            {h.path} <span class="text-faint">{h.symbols[0]?.addr}</span>
                            {!h.same_package && <span class="ml-2 text-faint">same name, different package ({h.package?.split(" ")[0] ?? "unpackaged"})</span>}
                          </div>
                        ))
                      )}
                    </td>
                    <td class="px-4 py-2">
                      {r.hits.length > 0 && <Procs procs={[...new Map(r.hits.flatMap((h) => h.procs).map((x) => [x.pid, x])).values()]} />}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div class="px-4 py-1.5 text-xs text-faint">{list().rows.filter((r) => r.hits.length).length} of {list().rows.length} named functions are in memory · {list().ms} ms</div>
          </div>
        )}
      </div>

      <div class="text-xs font-semibold uppercase tracking-wide text-muted">Or ask about any function</div>
      <div class="flex flex-wrap items-center gap-2">
        <input
          class="mono min-w-[16rem] flex-1 rounded-lg border border-border bg-bg px-3 py-2 text-fg placeholder:text-faint focus:border-accent focus:outline-none"
          placeholder="function name, or a regex — searched in every binary and library a live process maps"
          value={text()}
          disabled={busy()}
          onInput={(e) => setText(e.currentTarget.value)}
          onKeyDown={(e) => e.key === "Enter" && run()}
        />
        <button class="btn" disabled={busy() || !text().trim()} onClick={() => run()}>
          {busy() ? "Searching…" : "Find"}
        </button>
        <div class="flex flex-wrap gap-2">
          {EXAMPLES.map((s) => (
            <button class="mono rounded-full border border-border px-3 py-1 text-xs text-muted hover:bg-bg hover:text-fg disabled:opacity-50" disabled={busy()} onClick={() => run(s)}>
              {s}
            </button>
          ))}
        </div>
      </div>
      {error() && <div class="text-xs text-high">{error()}</div>}
      {result() && (
        <div class="space-y-2">
          <div class="text-xs text-muted">
            <span class="mono text-fg">{result().pattern}</span> is defined in <b class="text-fg">{result().files_with_symbol}</b> of {result().files_searched} mapped files,
            in memory in <b class="text-fg">{result().processes}</b> {result().processes === 1 ? "process" : "processes"} · {result().ms} ms
          </div>
          {result().hits.length === 0 ? (
            <div class="py-4 text-center text-muted">No live process maps a file that defines it.</div>
          ) : (
            <div class="divide-y divide-border rounded-lg border border-border">
              {result().hits.map((h) => (
                <div class="flex flex-wrap items-start gap-x-6 gap-y-1 px-4 py-2.5">
                  <div class="min-w-0 flex-1">
                    <div class="mono truncate" title={h.path}>{h.path}</div>
                    <div class="text-xs text-muted">
                      {h.package ?? <span class="text-medium">unpackaged</span>}
                      {h.advisories.length > 0 && <span class="ml-2 text-high">{h.advisories.join(", ")}</span>}
                    </div>
                    <div class="mono mt-1 flex flex-wrap gap-x-3 text-xs text-muted">
                      {h.symbols.map((s) => (
                        <span title={`${s.kind} · ${s.size} bytes`}>{s.name} <span class="text-faint">{s.addr}</span></span>
                      ))}
                      {h.more > 0 && <span class="text-faint">+{h.more} more</span>}
                    </div>
                  </div>
                  <Procs procs={h.procs} />
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
