#!/usr/bin/env node
/* bomtastic, from nothing but yeet and Node:
 *
 *   npx -y github:yeet-src/bomtastic [--peer host:3450 ...] [--port 3100]
 *
 * Fetches the release pack, applies it as the `bomtastic` service (the
 * scanner isolate behind a gateway on :3450), mounts one proxy route per
 * --peer so the fleet page can reach it, and serves the pages from the
 * same pack with yeetkit. Every other machine needs only
 * `yeet service apply -f <release url>`.
 */
import { spawn, spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";

const RELEASE = "https://github.com/yeet-src/bomtastic/releases/latest/download/bomtastic.tar.gz";
const SERVICE = "bomtastic";

const args = process.argv.slice(2);
const flag = (name, fallback) => { const i = args.indexOf(`--${name}`); return i < 0 ? fallback : args[i + 1]; };
const flags = (name) => args.flatMap((a, i) => (a === `--${name}` ? [args[i + 1]] : []));
if (args.includes("--help") || args.includes("-h")) {
  console.log(`bomtastic [--peer host:port ...] [--port 3100] [--service-port 3450] [--release <url or .tar.gz>] [--no-pages]`);
  process.exit(0);
}
const port = Number(flag("port", 3100));
const servicePort = Number(flag("service-port", 3450));
const release = flag("release", RELEASE);
const peers = flags("peer");
const pages = !args.includes("--no-pages");

const yeet = (...argv) => spawnSync("yeet", argv, { stdio: ["ignore", "pipe", "pipe"], encoding: "utf8" });
const fail = (msg) => { console.error(`bomtastic: ${msg}`); process.exit(1); };

if (yeet("--version").error) fail("yeet is not installed: curl -fsSL https://yeet.cx | sh");
if (yeet("service", "list").status !== 0) fail("the yeet daemon is not answering; is yeetd running?");

/* The pack, unpacked where the pages can read it. The scanner is applied
 * from the same copy, so the two halves are always the same build. */
const dir = join(process.env.XDG_CACHE_HOME ?? join(homedir(), ".cache"), "bomtastic", "pack");
await rm(dir, { recursive: true, force: true });
await mkdir(dir, { recursive: true });
let archive = release;
if (/^https?:\/\//.test(release)) {
  const res = await fetch(release, { redirect: "follow" });
  if (!res.ok) fail(`fetching ${release}: HTTP ${res.status}`);
  archive = join(dir, "bomtastic.tar.gz");
  await writeFile(archive, Buffer.from(await res.arrayBuffer()));
} else archive = resolve(release);
const tar = spawnSync("tar", ["xzf", archive, "-C", dir], { stdio: "inherit" });
if (tar.status !== 0) fail(`could not unpack ${archive}`);

if (servicePort !== 3450) {
  const toml = join(dir, "service.toml");
  await writeFile(toml, (await readFile(toml, "utf8")).replaceAll(":3450", `:${servicePort}`));
}

const applied = yeet("service", "apply", "-y", "-f", dir);
if (applied.status !== 0) fail(`yeet service apply failed:\n${applied.stderr || applied.stdout}`);
console.log(`bomtastic: scanner applied, gateway on :${servicePort}`);

for (const peer of peers) {
  const host = peer.split(":")[0].replaceAll(".", "-");
  const mounted = yeet("service", "mount", `${SERVICE}/gateway`, "-L", `/nodes/${host}`, "-U", `ws://${peer}/`, "-d", `bomtastic on ${peer}`);
  // Already mounted from an earlier run is fine; anything else is not.
  if (mounted.status !== 0 && !/already|exists/i.test(mounted.stderr)) fail(`mounting ${peer}:\n${mounted.stderr}`);
  console.log(`bomtastic: peer ${peer} at /nodes/${host}`);
}

if (!pages) process.exit(0);

// yeetkit exports no package.json; its main is src/runtime/index.js, two levels under the package root.
const yeetkit = join(dirname(createRequire(import.meta.url).resolve("yeetkit")), "..", "..", "bin", "yeetkit.mjs");
const hub = spawn(process.execPath, [yeetkit, "start", "--isolate", `ws://127.0.0.1:${servicePort}/app`, "--port", String(port)], {
  cwd: dir,
  stdio: "inherit",
  env: { ...process.env, BOM_GATEWAY: `127.0.0.1:${servicePort}`, BOM_SERVICE: SERVICE, BOM_NODE_PORT: String(port) },
});
for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => hub.kill(sig));
hub.on("exit", (code) => process.exit(code ?? 0));
