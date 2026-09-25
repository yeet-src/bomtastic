/* Who uses what: every binary connected to every shared library it
 * maps, as one picture. The data is shaped here, in the isolate, from
 * the shared scan; the layout and interaction happen in the browser
 * island, because that is where the pixels are. */
import { Show, createMemo } from "yeetkit";

import DependencyGraph from "@/lib/DependencyGraph.jsx";
import { buildGraph } from "@/lib/graph-data.js";
import { inventory, scan, scanning } from "@/lib/inventory.js";

export default function Graph() {
  if (!inventory() && !scanning()) scan();
  const data = createMemo(() => buildGraph(inventory()));

  return (
    <div class="space-y-5">
      <section class="flex flex-wrap items-end justify-between gap-4">
        <div class="max-w-2xl space-y-1">
          <h1 class="text-2xl font-semibold tracking-tight">Dependency graph</h1>
          <p class="text-muted">
            Every running binary, joined to the shared libraries it has mapped right now. Hover to trace one
            binary's dependencies or one library's users; click for the list.
          </p>
        </div>
        <Show when={data()}>
          <div class="text-xs text-faint">
            {data().counts.bins} binaries · {data().counts.files} libraries · {data().counts.fileLinks} mappings ·{" "}
            {data().counts.pkgs} packages
          </div>
        </Show>
      </section>

      <div class="card overflow-hidden">
        <Show when={data()} fallback={<div class="px-5 py-16 text-center text-muted">Scanning…</div>}>
          <DependencyGraph data={data()} />
        </Show>
      </div>
    </div>
  );
}
