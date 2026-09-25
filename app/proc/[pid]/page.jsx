/* One process: its binary, package, hash, sockets, and every library
 * it has mapped — with the package that owns each one. */
import { Index, Link, Show } from "yeetkit";

import { inventory, scan } from "@/lib/inventory.js";

export default function Proc(props) {
  if (!inventory()) scan();
  const pid = () => Number(props.params.pid);
  const proc = () => inventory()?.processes.find((p) => p.pid === pid()) ?? null;
  const file = () => inventory()?.files?.[proc()?.exe] ?? {};
  const pkgOf = (path) => inventory()?.files?.[path]?.package ?? null;
  const advisories = () => (inventory()?.vulns?.advisories ?? []).filter((a) => a.processes?.some((p) => p.pid === pid()));
  const listeners = () => inventory()?.listeners.filter((l) => l.pid === pid()) ?? [];
  const outbound = () => inventory()?.outbound.filter((c) => c.pid === pid()) ?? [];

  return (
    <div class="space-y-6">
      <div class="flex flex-wrap items-center gap-3">
        <Link href="/" class="btn-secondary">
          ← Inventory
        </Link>
        <h1 class="text-2xl font-semibold tracking-tight">
          <span class="mono text-muted">pid {pid()}</span>
          <Show when={proc()}>
            <span class="ml-2">{proc().comm}</span>
          </Show>
        </h1>
        <Show when={proc()?.exe_deleted}>
          <span class="badge bg-medium-soft text-medium">binary replaced on disk</span>
        </Show>
        <Show when={proc()?.container}>
          <span class="badge bg-accent-soft text-accent">container {proc().container}</span>
        </Show>
      </div>

      <Show
        when={proc()}
        fallback={
          <div class="card px-5 py-8 text-center text-muted">
            {inventory() ? "Not in the inventory — it exited, or it is a kernel thread." : "Scanning…"}
          </div>
        }
      >
        <div class="grid gap-6 lg:grid-cols-3">
          <section class="card lg:col-span-2">
            <h2 class="border-b border-border px-5 py-3.5 font-semibold">Process</h2>
            <dl class="grid grid-cols-[max-content_1fr] gap-x-8 gap-y-2.5 px-5 py-4">
              <Row k="Executable">
                <span class="mono break-all">{proc().exe}</span>
              </Row>
              <Row k="Package">
                {file().package ? (
                  <span class="mono">{file().package}</span>
                ) : proc().container ? (
                  <span class="text-muted">inside a container — host package database does not apply</span>
                ) : (
                  <span class="badge bg-medium-soft text-medium">unpackaged</span>
                )}
              </Row>
              <Row k="SHA-256">
                <span class="mono break-all text-muted">{file().sha256 ?? "—"}</span>
              </Row>
              <Row k="Command">
                <span class="mono break-all">{proc().cmdline}</span>
              </Row>
              <Row k="Working dir">
                <span class="mono">{proc().cwd}</span>
              </Row>
              <Row k="User">
                <span class={proc().uid === 0 ? "font-medium text-medium" : ""}>{proc().uid === 0 ? "root (0)" : proc().uid}</span>
              </Row>
              <Row k="Parent">
                <Link href={`/proc/${proc().ppid}`} class="mono text-accent hover:underline">
                  {proc().ppid}
                </Link>
              </Row>
              <Row k="Memory">
                <span class="tabular-nums">{Math.round(proc().rss / 1048576)} MB resident</span>
              </Row>
              <Row k="Cgroup">
                <span class="mono break-all text-muted">{proc().cgroup || "—"}</span>
              </Row>
            </dl>
          </section>

          <section class="card">
            <h2 class="border-b border-border px-5 py-3.5 font-semibold">Network</h2>
            <div class="space-y-3 px-5 py-4">
              <Show when={listeners().length || outbound().length} fallback={<p class="text-muted">No sockets.</p>}>
                <Index each={listeners()}>
                  {(l) => (
                    <div class="flex items-center gap-2">
                      <span class="badge bg-ok-soft text-ok">listen</span>
                      <span class="mono">
                        {l().proto} {l().local}
                      </span>
                    </div>
                  )}
                </Index>
                <Index each={outbound()}>
                  {(c) => (
                    <div class="flex items-center gap-2">
                      <span class="badge bg-info-soft text-info">out</span>
                      <span class="mono">{c().remote}</span>
                    </div>
                  )}
                </Index>
              </Show>
            </div>
          </section>
        </div>

        <Show when={advisories().length}>
          <section class="card border-high/30">
            <h2 class="border-b border-border px-5 py-3.5 font-semibold text-high">
              Pending security updates affecting this process
            </h2>
            <div class="divide-y divide-border">
              <Index each={advisories()}>
                {(a) => (
                  <div class="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-5 py-3">
                    <span class="badge bg-high-soft text-high">{a().severity}</span>
                    <a href={a().url} target="_blank" class="mono text-accent hover:underline">{a().id}</a>
                    <span class="mono text-xs text-muted">
                      {a().packages.map((p) => `${p.name} ${p.installed} → ${p.fixed ?? "?"}`).join("; ")}
                    </span>
                    <span class="text-xs text-muted">
                      {a().cves.map((c) => `${c.id}${c.score != null ? ` (${c.score})` : ""}`).join(", ") || a().title}
                    </span>
                  </div>
                )}
              </Index>
            </div>
          </section>
        </Show>

        <Show when={proc().stale_libs.length}>
          <section class="card border-medium/30">
            <h2 class="border-b border-border px-5 py-3.5 font-semibold text-medium">
              Stale libraries — updated on disk, old copy still mapped
            </h2>
            <div class="px-5 py-4">
              <Index each={proc().stale_libs}>{(l) => <div class="mono py-0.5">{l()}</div>}</Index>
            </div>
          </section>
        </Show>

        <section class="card overflow-hidden">
          <div class="flex items-center justify-between border-b border-border px-5 py-3.5">
            <h2 class="font-semibold">Mapped files</h2>
            <span class="text-xs text-muted">{proc().libs.length} files</span>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-left">
              <thead>
                <tr class="table-head border-b border-border bg-bg/60">
                  <th class="px-5 py-2 font-semibold">Path</th>
                  <th class="px-5 py-2 font-semibold">Package</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-border">
                <Index each={proc().libs}>
                  {(l) => (
                    <tr class="hover:bg-bg">
                      <td class="mono px-5 py-1.5">{l()}</td>
                      <td class="px-5 py-1.5">
                        {pkgOf(l()) ? (
                          <span class="mono text-muted">{pkgOf(l())}</span>
                        ) : proc().container ? (
                          <span class="text-faint">—</span>
                        ) : (
                          <span class="badge bg-medium-soft text-medium">unpackaged</span>
                        )}
                      </td>
                    </tr>
                  )}
                </Index>
              </tbody>
            </table>
          </div>
        </section>
      </Show>
    </div>
  );
}

function Row(props) {
  return (
    <>
      <dt class="text-muted">{props.k}</dt>
      <dd class="min-w-0">{props.children}</dd>
    </>
  );
}
