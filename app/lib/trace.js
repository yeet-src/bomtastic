"use yeet";

/* Live tracing, as tools the analyst can call.
 *
 * A snapshot says what exists; a trace says what is happening. Two BPF
 * programs — every exec, every TCP connect/accept — are attached only
 * for the seconds a call lasts, through yeetkit's refcounted probe, and
 * the events collected in that window are returned as a list the model
 * can reason about. Nothing here runs when nobody is asking.
 */
import { BpfObject, RingBuf } from "yeet:bpf";
import { createProbe } from "yeetkit";

import program from "#/app.bpf.o";

const MAX_SECONDS = 20;
const MAX_EVENTS = 400;

const str = (bytes) => {
  const values = Array.isArray(bytes) ? bytes : Object.values(bytes ?? {});
  let out = "";
  for (const b of values) {
    if (!b) break;
    out += String.fromCharCode(b);
  }
  return out;
};

const addr = (bytes, family) => {
  const v = Array.isArray(bytes) ? bytes : Object.values(bytes ?? {});
  if (family === 10) {
    const parts = [];
    for (let i = 0; i < 16; i += 2) parts.push(((v[i] << 8) | v[i + 1]).toString(16));
    return parts.join(":").replace(/(^|:)0(:0)+(:|$)/, "::");
  }
  return v.slice(0, 4).join(".");
};

/* One probe per program, each with its own listener set. */
function makeProbe({ name, map, struct, attach, decode }) {
  const listeners = new Set();
  const probe = createProbe({
    name,
    linger: 3000,
    async start() {
      const control = await new BpfObject({ exe: program.exe })
        .bind(map, { kind: "ringbuf", btf_struct: struct })
        .attach(attach)
        .start();
      await new RingBuf(control, map).subscribe((wrapped) => {
        try {
          const row = decode(wrapped?.[struct] ?? wrapped);
          for (const l of listeners) l(row);
        } catch {
          /* one bad event costs one row */
        }
      });
      return { control };
    },
    stop: ({ control }) => control.stop(),
  });

  /** Collect events for `seconds`, optionally filtered. */
  return async function collect(seconds, keep = () => true) {
    const s = Math.min(MAX_SECONDS, Math.max(1, Number(seconds) || 5));
    const { release } = await probe.acquire("trace");
    const rows = [];
    const listener = (row) => {
      if (rows.length < MAX_EVENTS && keep(row)) rows.push(row);
    };
    listeners.add(listener);
    try {
      await new Promise((r) => setTimeout(r, s * 1000));
    } finally {
      listeners.delete(listener);
      release();
    }
    return { seconds: s, events: rows.length, truncated: rows.length >= MAX_EVENTS, rows };
  };
}

const execs = makeProbe({
  name: "execs",
  map: "execs",
  struct: "exec_event",
  attach: "on_exec",
  decode: (e) => ({
    at: new Date().toISOString().slice(11, 23),
    pid: Number(e.pid),
    ppid: Number(e.ppid),
    uid: Number(e.uid),
    comm: str(e.comm),
    file: str(e.filename),
  }),
});

const connects = makeProbe({
  name: "connects",
  map: "connects",
  struct: "connect_event",
  attach: "on_sock_state",
  decode: (e) => ({
    at: new Date().toISOString().slice(11, 23),
    pid: Number(e.pid),
    uid: Number(e.uid),
    comm: str(e.comm),
    direction: Number(e.direction) === 1 ? "in" : "out",
    remote: `${addr(e.daddr, Number(e.family))}:${Number(e.dport)}`,
    family: Number(e.family) === 10 ? "ipv6" : "ipv4",
  }),
});

/**
 * Every execve on the host for `seconds` (max 20), summarised.
 * `filter` matches comm, file or a parent pid.
 */
export async function traceExecs({ seconds = 5, filter = "" } = {}) {
  const f = String(filter ?? "").toLowerCase();
  const result = await execs(seconds, (r) => !f || r.comm.toLowerCase().includes(f) || r.file.toLowerCase().includes(f) || String(r.ppid) === f || String(r.pid) === f);
  return { ...result, summary: summarize(result.rows, (r) => `${r.comm} ← ppid ${r.ppid}`) };
}

/**
 * Every TCP connect (out) and accept (in) for `seconds` (max 20).
 * `pid` restricts to one process; `filter` matches comm or remote.
 */
export async function traceConnects({ seconds = 5, pid = null, filter = "", inbound = false } = {}) {
  const f = String(filter ?? "").toLowerCase();
  const want = pid ? Number(pid) : null;
  /* Outbound connects run in the caller's context, so the pid is the
   * process that asked. Accepts complete in softirq and the pid on the
   * CPU is whoever was running — useful for "what ports get hit", not
   * for "who"; hence off unless asked. */
  const result = await connects(
    seconds,
    (r) => (inbound || r.direction === "out") && (want === null || r.pid === want) && (!f || r.comm.toLowerCase().includes(f) || r.remote.toLowerCase().includes(f)),
  );
  return { ...result, summary: summarize(result.rows, (r) => `${r.comm}(${r.pid}) ${r.direction} ${r.remote}`) };
}

function summarize(rows, key) {
  const counts = new Map();
  for (const r of rows) counts.set(key(r), (counts.get(key(r)) ?? 0) + 1);
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 25)
    .map(([k, n]) => `${k} ×${n}`);
}
