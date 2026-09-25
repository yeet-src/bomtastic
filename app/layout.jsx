/* The shell: a top bar with the brand, live counts, and the export
 * action. The layout survives navigation, so the counts stay put while
 * the page below changes. */
import { Link } from "yeetkit";

import { inventory, scanning } from "@/lib/inventory.js";

export default function Layout(props) {
  const counts = () => inventory()?.counts ?? {};
  const stat = (key) => counts()[key] ?? "–";

  return (
    <div class="min-h-screen bg-bg text-fg">
      <header class="sticky top-0 z-10 border-b border-border bg-surface/90 backdrop-blur">
        <div class="mx-auto flex w-full max-w-6xl flex-wrap items-center gap-x-6 gap-y-2 px-6 py-3">
          <Link href="/" end class="flex items-center gap-2.5">
            <img src="/fecm.png" alt="" width="32" height="30" class="h-8 w-auto shrink-0" />
            <span class="font-semibold tracking-tight">
              yeet <span class="text-accent">BOM</span>
            </span>
          </Link>

          <nav class="flex items-center gap-1 text-[13px]">
            <Link href="/" end class="rounded-md px-2.5 py-1 text-muted hover:bg-bg hover:text-fg" activeClass="!bg-accent-soft !text-accent font-medium">
              Inventory
            </Link>
            <Link href="/graph" class="rounded-md px-2.5 py-1 text-muted hover:bg-bg hover:text-fg" activeClass="!bg-accent-soft !text-accent font-medium">
              Graph
            </Link>
            <Link href="/fleet" class="rounded-md px-2.5 py-1 text-muted hover:bg-bg hover:text-fg" activeClass="!bg-accent-soft !text-accent font-medium">
              Fleet
            </Link>
          </nav>

          <nav class="hidden items-center gap-4 text-muted lg:flex">
            <span class="flex items-center gap-1.5">
              <span class="pulse-dot" style={scanning() ? "" : "visibility:hidden"} />
              <span>{scanning() ? "scanning" : "live"}</span>
            </span>
            <span>
              <span class="font-medium text-fg">{stat("processes")}</span> processes
            </span>
            <span>
              <span class="font-medium text-fg">{stat("binaries")}</span> binaries
            </span>
            <span>
              <span class="font-medium text-fg">{stat("libraries")}</span> libraries
            </span>
            <span>
              <span class={`font-medium ${counts().high ? "text-high" : "text-fg"}`}>{stat("findings")}</span> findings
            </span>
          </nav>

          <a href="/api/sbom" target="_blank" class="btn-secondary ml-auto">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 3v12m0 0l-4-4m4 4l4-4M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2" />
            </svg>
            Export CycloneDX
          </a>
        </div>
      </header>

      <main class="mx-auto w-full max-w-7xl px-6 py-8">{props.children}</main>
    </div>
  );
}
