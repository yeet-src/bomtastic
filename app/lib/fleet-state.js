/* The fleet, cached in the isolate. The walk dials every node, so the
 * strip on the inventory page, the fleet page and a node's drill-down
 * share one result and refresh it only when asked or when it is stale.
 *
 * Rows land one at a time: the route list comes first and every node
 * is shown pending, then each node's call replaces its own row when it
 * answers. A dead node times out on its own row and delays nobody. */
import { createSignal } from "yeetkit";

import { fleetNode, fleetRoutes } from "@/lib/fleet.js";

const FRESH_MS = 60_000;
const ORDER = { red: 0, amber: 1, grey: 2, pending: 3, green: 4 };

export const [fleetResult, setFleetResult] = createSignal(null);
export const [fleetLoading, setFleetLoading] = createSignal(false);
let loadedAt = 0;
let inflight = null;
let generation = 0;

const pending = (route) => ({ ...route, ok: false, pending: true, verdict: { level: "pending", text: "asking…" } });

const sorted = (nodes) => nodes.slice().sort((a, b) => ORDER[a.verdict.level] - ORDER[b.verdict.level] || a.name.localeCompare(b.name));

export function loadFleet({ force = false } = {}) {
  if (inflight) return inflight;
  if (!force && fleetResult() && Date.now() - loadedAt < FRESH_MS) return Promise.resolve(fleetResult());
  const gen = ++generation;
  setFleetLoading(true);
  inflight = (async () => {
    const { routes, ...rest } = await fleetRoutes();
    let nodes = routes.map(pending);
    setFleetResult({ ...rest, nodes: sorted(nodes) });
    await Promise.all(
      routes.map(async (route) => {
        const row = { ...route, ...(await fleetNode(route.path)) };
        if (gen !== generation) return;
        nodes = nodes.map((n) => (n.path === route.path ? row : n));
        setFleetResult({ ...rest, nodes: sorted(nodes) });
      }),
    );
    loadedAt = Date.now();
    return fleetResult();
  })()
    .catch((error) => {
      const r = { error: String(error?.message ?? error), nodes: [] };
      setFleetResult(r);
      return r;
    })
    .finally(() => {
      setFleetLoading(false);
      inflight = null;
    });
  return inflight;
}

export const nodeBySlug = (slug) => fleetResult()?.nodes?.find((n) => n.slug === slug) ?? null;

/** What the inventory page's strip says: how many nodes, how many red, the worst one. */
export function fleetSummary() {
  const r = fleetResult();
  if (!r || r.error || !r.nodes.length) return null;
  const nodes = sorted(r.nodes);
  const by = (level) => nodes.filter((n) => n.verdict.level === level).length;
  const settled = nodes.filter((n) => !n.pending);
  const worst = settled[0] ?? null;
  return {
    total: nodes.length,
    red: by("red"),
    amber: by("amber"),
    green: by("green"),
    grey: by("grey"),
    pending: by("pending"),
    level: worst?.verdict.level ?? "pending",
    worst: worst && worst.verdict.level !== "green" && worst.verdict.level !== "grey" ? worst : null,
  };
}
