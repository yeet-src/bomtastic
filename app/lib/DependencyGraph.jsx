"use client";

/* The graph, in the browser.
 *
 * Runs here because layout and hover are per-viewer and per-frame:
 * a force simulation over four hundred nodes is a few hundred ticks
 * of arithmetic, and a hover is a repaint — neither should cross a
 * socket. The isolate hands over the nodes and edges as props; this
 * component owns the SVG from there.
 *
 * d3 owns the drawing (selection, zoom, drag, force) and Solid owns the
 * controls around it. The two meet in `render()`, which is called
 * whenever a control changes.
 */
import { createEffect, createSignal, onCleanup, onMount, untrack, Show, For } from "solid-js";
import { forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY } from "d3-force";
import { select } from "d3-selection";
import { zoom, zoomIdentity } from "d3-zoom";
import { drag } from "d3-drag";

const COLOR = {
  bin: "#818cf8",
  binUnpackaged: "#fbbf24",
  binContainer: "#64748b",
  lib: "#22d3ee",
  pkg: "#2dd4bf",
  libUnpackaged: "#fbbf24",
  libContainer: "#475569",
  link: "#334155",
  linkHot: "#a5b4fc",
  halo: "#0b0f17", // the ground, so a stroke reads as a gap
  labelBin: "#e5e7eb",
  labelLib: "#94a3b8",
  focus: "#f8fafc",
};

export default function DependencyGraph(props) {
  const [mode, setMode] = createSignal("pkg"); // pkg | file
  const [hideAbove, setHideAbove] = createSignal(60); // % of binaries; libs used by more are hidden
  const [showContainers, setShowContainers] = createSignal(false);
  const [selected, setSelected] = createSignal(null);
  const [hover, setHover] = createSignal(null);
  const [stats, setStats] = createSignal({ nodes: 0, links: 0, hidden: 0 });

  let svgEl;
  let wrap;
  let simulation;
  let positions = new Map(); // id -> {x,y} kept across re-renders so toggles do not reshuffle

  /* ---- data for the current view ---- */
  const view = () => {
    const g = props.data;
    if (!g) return { nodes: [], links: [], hidden: [] };
    const bins = g.bins.filter((b) => showContainers() || !b.container);
    const binIds = new Set(bins.map((b) => b.id));
    const libs = (mode() === "pkg" ? g.pkgs : g.files).filter((l) => showContainers() || !l.container);
    const rawLinks = (mode() === "pkg" ? g.pkgLinks : g.fileLinks).filter((l) => binIds.has(l.source));

    /* degree within the visible set, so the threshold means what it says */
    const degree = new Map();
    for (const l of rawLinks) degree.set(l.target, (degree.get(l.target) ?? 0) + 1);
    const cutoff = (hideAbove() / 100) * bins.length;
    const hidden = libs.filter((l) => (degree.get(l.id) ?? 0) > cutoff && hideAbove() < 100);
    const hiddenIds = new Set(hidden.map((l) => l.id));
    const shown = libs.filter((l) => !hiddenIds.has(l.id) && (degree.get(l.id) ?? 0) > 0);
    const shownIds = new Set([...binIds, ...shown.map((l) => l.id)]);
    const links = rawLinks.filter((l) => shownIds.has(l.source) && shownIds.has(l.target));
    const nodes = [...bins, ...shown].map((n) => ({ ...n, degree: n.kind === "bin" ? undefined : degree.get(n.id) ?? 0 }));
    return { nodes, links, hidden: hidden.map((l) => ({ ...l, degree: degree.get(l.id) ?? 0 })) };
  };

  const radius = (n, total) => (n.kind === "bin" ? 5 + Math.min(6, Math.sqrt(n.pids)) : 3 + 14 * Math.sqrt((n.degree ?? 0) / Math.max(1, total)));
  const fill = (n) =>
    n.kind === "bin"
      ? n.container
        ? COLOR.binContainer
        : n.package
          ? COLOR.bin
          : COLOR.binUnpackaged
      : n.kind === "pkg"
        ? COLOR.pkg
        : n.container
          ? COLOR.libContainer
          : n.package
            ? COLOR.lib
            : COLOR.libUnpackaged;

  /* ---- drawing ---- */
  let g; // the zoomable group
  let linkSel;
  let nodeSel;
  let labelSel;
  let current = { nodes: [], links: [] };

  const render = () => {
    if (!svgEl) return;
    const { nodes, links, hidden } = view();
    const bins = nodes.filter((n) => n.kind === "bin").length;
    setStats({ nodes: nodes.length, links: links.length, hidden: hidden.length });

    for (const n of nodes) {
      const p = positions.get(n.id);
      if (p) Object.assign(n, p);
    }
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const linkObjs = links.map((l) => ({ source: byId.get(l.source), target: byId.get(l.target) })).filter((l) => l.source && l.target);
    current = { nodes, links: linkObjs };

    const width = wrap.clientWidth || 1200;
    const height = wrap.clientHeight || 800;

    simulation?.stop();
    simulation = forceSimulation(nodes)
      .force("link", forceLink(linkObjs).distance((l) => (l.target.kind === "pkg" ? 46 : 34)).strength(0.35))
      .force("charge", forceManyBody().strength((n) => (n.kind === "bin" ? -90 : -40)).distanceMax(420))
      .force("collide", forceCollide((n) => radius(n, bins) + 3).iterations(2))
      .force("x", forceX(width / 2).strength(0.03))
      .force("y", forceY(height / 2).strength(0.03))
      .force("center", forceCenter(width / 2, height / 2))
      .stop();
    /* Settle synchronously: a static picture that is right beats one
     * that wobbles into place. */
    const ticks = positions.size ? 120 : 300;
    for (let i = 0; i < ticks; i++) simulation.tick();
    for (const n of nodes) positions.set(n.id, { x: n.x, y: n.y });

    linkSel = g
      .select("g.links")
      .selectAll("line")
      .data(linkObjs, (d) => `${d.source.id}|${d.target.id}`)
      .join("line")
      .attr("stroke", COLOR.link)
      .attr("stroke-opacity", 0.7)
      .attr("stroke-width", 1);

    nodeSel = g
      .select("g.nodes")
      .selectAll("circle")
      .data(nodes, (d) => d.id)
      .join("circle")
      .attr("r", (d) => radius(d, bins))
      .attr("fill", fill)
      .attr("stroke", COLOR.halo)
      .attr("stroke-width", 1.5)
      .style("cursor", "pointer")
      .on("mouseenter", (_, d) => setHover(d))
      .on("mouseleave", () => setHover(null))
      .on("click", (event, d) => {
        event.stopPropagation();
        setSelected(selected()?.id === d.id ? null : d);
      })
      .call(
        drag()
          .on("start", (event, d) => {
            d.fx = d.x;
            d.fy = d.y;
          })
          .on("drag", (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
            d.x = event.x;
            d.y = event.y;
            positions.set(d.id, { x: d.x, y: d.y });
            paint();
          })
          .on("end", (event, d) => {
            d.fx = null;
            d.fy = null;
          }),
      );

    labelSel = g
      .select("g.labels")
      .selectAll("text")
      .data(
        nodes.filter((n) => n.kind === "bin" || n.kind === "pkg" || (n.degree ?? 0) >= 3),
        (d) => d.id,
      )
      .join("text")
      .text((d) => d.label)
      .attr("font-size", (d) => (d.kind === "bin" ? 10 : 9))
      .attr("font-weight", (d) => (d.kind === "bin" ? 600 : 400))
      .attr("fill", (d) => (d.kind === "bin" ? COLOR.labelBin : COLOR.labelLib))
      .attr("paint-order", "stroke")
      .attr("stroke", COLOR.halo)
      .attr("stroke-width", 3)
      .attr("stroke-linejoin", "round")
      .attr("pointer-events", "none")
      .attr("dy", (d) => radius(d, bins) + 10)
      .attr("text-anchor", "middle");

    /* Untracked: `paint` reads the hover and selection signals, and
     * this runs inside the layout effect. Tracked, every hover would
     * re-run the simulation and the whole graph would drift. */
    untrack(paint);
  };

  /* Positions and highlight, without re-running the simulation. */
  const paint = () => {
    if (!linkSel) return;
    const focus = hover() ?? selected();
    const near = new Set();
    if (focus) {
      near.add(focus.id);
      for (const l of current.links) {
        if (l.source.id === focus.id) near.add(l.target.id);
        if (l.target.id === focus.id) near.add(l.source.id);
      }
    }
    const touches = (l) => focus && (l.source.id === focus.id || l.target.id === focus.id);

    linkSel
      .attr("x1", (d) => d.source.x)
      .attr("y1", (d) => d.source.y)
      .attr("x2", (d) => d.target.x)
      .attr("y2", (d) => d.target.y)
      .attr("stroke", (d) => (touches(d) ? COLOR.linkHot : COLOR.link))
      .attr("stroke-opacity", (d) => (focus ? (touches(d) ? 0.95 : 0.06) : 0.7))
      .attr("stroke-width", (d) => (touches(d) ? 1.6 : 1));
    nodeSel
      .attr("cx", (d) => d.x)
      .attr("cy", (d) => d.y)
      .attr("opacity", (d) => (focus ? (near.has(d.id) ? 1 : 0.15) : 1))
      .attr("stroke", (d) => (d.id === focus?.id ? COLOR.focus : COLOR.halo));
    labelSel
      .attr("x", (d) => d.x)
      .attr("y", (d) => d.y)
      .attr("opacity", (d) => (focus ? (near.has(d.id) ? 1 : 0.1) : 1));
  };

  onMount(() => {
    const svg = select(svgEl);
    g = svg.append("g");
    g.append("g").attr("class", "links");
    g.append("g").attr("class", "nodes");
    g.append("g").attr("class", "labels");
    svg.call(
      zoom()
        .scaleExtent([0.2, 6])
        .on("zoom", (event) => g.attr("transform", event.transform)),
    );
    svg.on("click", () => setSelected(null));
    render();
    const ro = new ResizeObserver(() => paint());
    ro.observe(wrap);
    onCleanup(() => {
      ro.disconnect();
      simulation?.stop();
    });
  });

  createEffect(() => {
    mode();
    hideAbove();
    showContainers();
    props.data;
    if (g) untrack(render);
  });
  createEffect(() => {
    hover();
    selected();
    paint();
  });

  const reset = () => {
    positions = new Map();
    select(svgEl).call(zoom().transform, zoomIdentity);
    render();
  };

  /* ---- side panel content ---- */
  const neighbours = () => {
    const f = selected();
    if (!f) return [];
    const out = [];
    for (const l of current.links) {
      if (l.source.id === f.id) out.push(l.target);
      else if (l.target.id === f.id) out.push(l.source);
    }
    return out.sort((a, b) => (b.degree ?? b.pids ?? 0) - (a.degree ?? a.pids ?? 0) || a.label.localeCompare(b.label));
  };

  return (
    <div class="flex h-[calc(100vh-10rem)] min-h-[560px] flex-col">
      {/* controls */}
      <div class="flex flex-wrap items-center gap-x-5 gap-y-2 border-b border-border px-5 py-3 text-[13px]">
        <div class="inline-flex overflow-hidden rounded-lg border border-border">
          <button class={`px-3 py-1.5 ${mode() === "pkg" ? "bg-accent-strong text-white" : "hover:bg-bg"}`} onClick={() => setMode("pkg")}>
            By package
          </button>
          <button class={`px-3 py-1.5 ${mode() === "file" ? "bg-accent-strong text-white" : "hover:bg-bg"}`} onClick={() => setMode("file")}>
            By library
          </button>
        </div>

        <label class="flex items-center gap-2 text-muted">
          Hide libraries used by more than
          <input
            type="range"
            min="10"
            max="100"
            step="5"
            value={hideAbove()}
            onInput={(e) => setHideAbove(Number(e.currentTarget.value))}
            class="w-32 accent-accent"
          />
          <span class="w-16 tabular-nums text-fg">{hideAbove() === 100 ? "show all" : `${hideAbove()}%`}</span>
          of binaries
        </label>

        <label class="flex items-center gap-2 text-muted">
          <input type="checkbox" checked={showContainers()} onChange={(e) => setShowContainers(e.currentTarget.checked)} class="accent-accent" />
          Include container processes
        </label>

        <button class="btn-secondary ml-auto" onClick={reset}>
          Reset layout
        </button>
      </div>

      <div class="flex min-h-0 flex-1">
        {/* canvas */}
        <div ref={wrap} class="relative min-w-0 flex-1 overflow-hidden bg-[radial-gradient(#1f2937_1px,transparent_1px)] [background-size:22px_22px]">
          <svg ref={svgEl} class="h-full w-full select-none" />

          {/* legend + stats */}
          <div class="pointer-events-none absolute bottom-3 left-3 space-y-1 rounded-lg border border-border bg-surface/90 px-3 py-2 text-xs text-muted backdrop-blur">
            <div class="flex items-center gap-2"><Dot c={COLOR.bin} /> binary <span class="text-faint">packaged</span></div>
            <div class="flex items-center gap-2"><Dot c={COLOR.binUnpackaged} /> binary or library <span class="text-faint">unpackaged</span></div>
            <div class="flex items-center gap-2"><Dot c={mode() === "pkg" ? COLOR.pkg : COLOR.lib} /> {mode() === "pkg" ? "package" : "shared library"} <span class="text-faint">sized by users</span></div>
            <Show when={showContainers()}>
              <div class="flex items-center gap-2"><Dot c={COLOR.binContainer} /> in a container</div>
            </Show>
            <div class="pt-1 text-faint">
              {stats().nodes} nodes · {stats().links} edges · {stats().hidden} ubiquitous hidden · drag, scroll to zoom, click for detail
            </div>
          </div>

          {/* hover tooltip */}
          <Show when={hover()}>
            <div class="pointer-events-none absolute top-3 left-3 max-w-sm rounded-lg border border-border bg-surface/95 px-3 py-2 text-xs shadow-sm backdrop-blur">
              <div class="font-semibold text-fg">{hover().label}</div>
              <div class="mono break-all text-muted">{hover().path}</div>
              <div class="text-muted">
                {hover().kind === "bin"
                  ? `${hover().pids} process${hover().pids === 1 ? "" : "es"} · ${hover().package ?? (hover().container ? `container ${hover().container}` : "unpackaged")}`
                  : `used by ${hover().degree} binar${hover().degree === 1 ? "y" : "ies"}${hover().kind === "pkg" ? ` · ${hover().files} librar${hover().files === 1 ? "y" : "ies"}` : hover().package ? ` · ${hover().package}` : " · unpackaged"}`}
              </div>
            </div>
          </Show>
        </div>

        {/* side panel */}
        <Show when={selected()}>
          <aside class="w-80 shrink-0 overflow-y-auto border-l border-border bg-surface">
            <div class="border-b border-border px-4 py-3">
              <div class="flex items-start justify-between gap-2">
                <div class="min-w-0">
                  <div class="flex items-center gap-2">
                    <Dot c={fill(selected())} />
                    <span class="truncate font-semibold">{selected().label}</span>
                  </div>
                  <div class="mono mt-1 break-all text-xs text-muted">{selected().path}</div>
                </div>
                <button class="text-faint hover:text-fg" onClick={() => setSelected(null)} aria-label="close">
                  ✕
                </button>
              </div>
              <div class="mt-2 text-xs text-muted">
                {selected().kind === "bin"
                  ? `${selected().pids} running · ${selected().comms?.join(", ")}`
                  : `${neighbours().length} binaries depend on this`}
              </div>
              <Show when={selected().kind === "bin" && !selected().container}>
                <div class="mt-1 text-xs">
                  {selected().package ? <span class="mono text-muted">{selected().package}</span> : <span class="badge bg-medium-soft text-medium">unpackaged</span>}
                </div>
              </Show>
            </div>
            <div class="px-4 py-3">
              <div class="table-head mb-2">{selected().kind === "bin" ? (mode() === "pkg" ? "Depends on packages" : "Maps libraries") : "Used by"}</div>
              <ul class="space-y-1">
                <For each={neighbours()}>
                  {(n) => (
                    <li>
                      <button
                        class="flex w-full items-center gap-2 rounded-md px-2 py-1 text-left hover:bg-bg"
                        onMouseEnter={() => setHover(n)}
                        onMouseLeave={() => setHover(null)}
                        onClick={() => setSelected(n)}
                      >
                        <Dot c={fill(n)} />
                        <span class="min-w-0 flex-1 truncate">{n.label}</span>
                        <span class="text-xs tabular-nums text-faint">{n.kind === "bin" ? `×${n.pids}` : n.degree}</span>
                      </button>
                    </li>
                  )}
                </For>
              </ul>
            </div>
          </aside>
        </Show>
      </div>
    </div>
  );
}

function Dot(props) {
  return <span class="inline-block h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: props.c }} />;
}
