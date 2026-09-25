/* The pieces the inventory page and the fleet pages share: the card
 * with a header, the table, the badge colours, and the relative
 * timestamp. Rendered in the isolate like everything else. */
import { Link, Show } from "yeetkit";

export const ADVISORY = {
  critical: "bg-high-soft text-high",
  important: "bg-high-soft text-high",
  high: "bg-high-soft text-high",
  moderate: "bg-medium-soft text-medium",
  medium: "bg-medium-soft text-medium",
  low: "bg-info-soft text-info",
};

export const SEVERITY = {
  high: { badge: "bg-high-soft text-high", bar: "bg-high" },
  medium: { badge: "bg-medium-soft text-medium", bar: "bg-medium" },
  info: { badge: "bg-info-soft text-info", bar: "bg-info" },
};

export const LEVEL = {
  red: { dot: "bg-high", badge: "bg-high-soft text-high", ring: "border-high/40", text: "text-high" },
  amber: { dot: "bg-medium", badge: "bg-medium-soft text-medium", ring: "border-medium/40", text: "text-medium" },
  green: { dot: "bg-ok", badge: "bg-ok-soft text-ok", ring: "", text: "text-ok" },
  grey: { dot: "bg-faint", badge: "bg-bg text-muted", ring: "", text: "text-muted" },
  pending: { dot: "bg-faint animate-pulse", badge: "bg-bg text-faint", ring: "opacity-70", text: "text-faint" },
};

/** Seconds to a short relative age. */
export const ago = (s) => (s < 90 ? `${s}s` : s < 5400 ? `${Math.round(s / 60)}m` : s < 172800 ? `${Math.round(s / 3600)}h` : `${Math.round(s / 86400)}d`);

/** An ISO timestamp to "12m ago". */
export const since = (iso) => `${ago(Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000)))} ago`;

export function Section(props) {
  return (
    <section class="card overflow-hidden">
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-border px-5 py-3.5">
        <div>
          <h2 class="font-semibold">{props.title}</h2>
          <Show when={props.subtitle}>
            <p class="text-xs text-muted">{props.subtitle}</p>
          </Show>
        </div>
        {props.actions}
      </div>
      {props.children}
    </section>
  );
}

export function Table(props) {
  return (
    <div class="overflow-x-auto">
      <table class="w-full text-left">
        <thead>
          <tr class="table-head border-b border-border bg-bg/60">
            {props.head.map((h) => (
              <th class="px-5 py-2 font-semibold">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody class="divide-y divide-border">{props.children}</tbody>
      </table>
    </div>
  );
}

/** A pid: a link to the process page here, plain text for another host. */
export function Pid(props) {
  return (
    <Show when={props.pid} fallback={<span class="text-faint">?</span>}>
      <Show when={!props.remote} fallback={<span class="mono text-muted">{props.pid}</span>}>
        <Link href={`/proc/${props.pid}`} class="mono text-accent hover:underline">
          {props.pid}
        </Link>
      </Show>
    </Show>
  );
}

export function Empty(props) {
  return <div class="px-5 py-8 text-center text-muted">{props.children}</div>;
}
