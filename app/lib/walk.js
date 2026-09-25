/* The /proc walk: everything the scan needs from sys_graph, and the
 * first fold of it (which files each pid maps, which pid holds each
 * socket inode). Plain isolate module with no imports beyond graph.js,
 * so the same code runs inline or bundled into `public/scan-worker.js`
 * and executed in a `Worker` — a second isolate that dies when the walk
 * is done and takes the raw map tables with it.
 */
import { graphOnce, procsRobust } from "./graph.js";

export async function walk(progress = () => {}) {
  const timings = {};
  let mark = Date.now();
  const lap = (name) => { const now = Date.now(); timings[name] = now - mark; mark = now; };

  progress("walking /proc");
  const [procs, { host }] = await Promise.all([
    procsRobust(`uid exe cwd root cmdline stat { comm ppid starttime rss_bytes } cgroups { pathname }`),
    graphOnce(`{ host { boot_time_secs ticks_per_second } }`),
  ]);
  lap("procs");

  progress("reading memory maps");
  const mapped = await procsRobust(`maps { kind path }`);
  const libsByPid = [];
  for (const p of mapped) {
    const libs = new Set();
    for (const m of p.maps) if (m.kind === "PATH" && m.path) libs.add(m.path);
    libsByPid.push([p.pid, [...libs]]);
  }
  lap("maps");

  progress("attributing sockets");
  const [withFds, net] = await Promise.all([
    procsRobust(`fds { inode kind }`),
    graphOnce(
      `{ tcp { state inode uid local_address { addr } remote_address { addr } }
         tcp6 { state inode uid local_address { addr } remote_address { addr } }
         udp { inode uid local_address { addr } } udp6 { inode uid local_address { addr } } }`,
    ),
  ]);
  const pidByInode = [];
  for (const p of withFds) for (const fd of p.fds) if (fd.kind === "SOCKET" && fd.inode != null) pidByInode.push([fd.inode, p.pid]);
  lap("sockets");

  progress("listing containers");
  let containers = [];
  try {
    const d = await graphOnce(`{ docker { list_containers { id names image image_id state command created } } }`);
    containers = (d.docker?.list_containers ?? []).map((c) => ({
      id: (c.id ?? "").slice(0, 12),
      name: (c.names?.[0] ?? "").replace(/^\//, ""),
      image: c.image,
      image_id: c.image_id,
      state: c.state,
      command: c.command,
      created: c.created,
    }));
  } catch {
    /* no docker on this host */
  }
  lap("containers");

  return { procs, host, libsByPid, pidByInode, net, containers, timings };
}
