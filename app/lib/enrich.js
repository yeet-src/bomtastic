"use server";

/* The filesystem's half of the inventory. Runs in Node, the only
 * runtime here with a filesystem and a shell — so this is where the
 * package database is consulted and files are hashed. The isolate calls
 * it with a list of paths and gets a map back.
 *
 * Both rpm and dpkg are handled; whichever answers first for the host
 * is used. A file owned by no package is reported as `package: null`,
 * which is itself a finding.
 */
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";

const HASH_LIMIT = 256 * 1024 * 1024;

const run = (cmd, args) =>
  new Promise((resolve) =>
    execFile(cmd, args, { maxBuffer: 64 * 1024 * 1024 }, (error, stdout, stderr) =>
      resolve({ code: error?.code ?? 0, stdout: String(stdout), stderr: String(stderr), missing: error?.code === "ENOENT" }),
    ),
  );

export async function enrich({ paths = [], hash = [] }) {
  const out = {};
  for (const p of paths) out[p] = { package: null, sha256: null, mtime: null };

  const owners = await packageOwners(paths);
  for (const [p, pkg] of owners) if (out[p]) out[p].package = pkg;

  await Promise.all(
    hash.map(async (p) => {
      try {
        const s = await stat(p);
        out[p] ??= { package: null, sha256: null, mtime: null };
        out[p].mtime = Math.floor(s.mtimeMs / 1000);
        if (s.size <= HASH_LIMIT) out[p].sha256 = await sha256(p);
      } catch {
        /* unreadable or gone — stays null */
      }
    }),
  );

  return out;
}

/* One dump of the whole package database — every file of every package —
 * rather than one query per path. rpm's per-invocation cost is ~20ms
 * and a host process tree maps six hundred distinct files; the dump is
 * about a second once and then a Map lookup. Cached for ten minutes,
 * which is longer than any scan and shorter than any package upgrade
 * anyone will wait around for. */
let fileIndex = null;
let indexedAt = 0;
const INDEX_TTL = 10 * 60 * 1000;

async function packageOwners(paths) {
  const owners = new Map();
  if (!paths.length) return owners;
  const index = await packageIndex();
  for (const p of paths) {
    const pkg = index.get(p);
    if (pkg) owners.set(p, pkg);
  }
  return owners;
}

async function packageIndex() {
  if (fileIndex && Date.now() - indexedAt < INDEX_TTL) return fileIndex;
  const index = new Map();

  const rpm = await run("rpm", ["-qa", "--queryformat", "[%{=NAME} %{=EVR}\t%{FILENAMES}\n]"]);
  if (!rpm.missing && rpm.stdout) {
    for (const line of rpm.stdout.split("\n")) {
      const tab = line.indexOf("\t");
      if (tab > 0) index.set(line.slice(tab + 1), line.slice(0, tab));
    }
  } else {
    /* dpkg: package names from the status database, file lists from
     * /var/lib/dpkg/info/<pkg>.list. */
    const dpkg = await run("dpkg-query", ["-W", "-f", "${Package} ${Version}\t${Package}\n"]);
    if (!dpkg.missing) {
      const { readFile } = await import("node:fs/promises");
      await Promise.all(
        dpkg.stdout.split("\n").filter(Boolean).map(async (line) => {
          const [label, name] = line.split("\t");
          for (const suffix of [name, `${name}:amd64`, `${name}:arm64`]) {
            const list = await readFile(`/var/lib/dpkg/info/${suffix}.list`, "utf8").catch(() => null);
            if (list) {
              for (const f of list.split("\n")) if (f) index.set(f, label);
              break;
            }
          }
        }),
      );
    }
  }

  fileIndex = index;
  indexedAt = Date.now();
  return index;
}

function sha256(path) {
  return new Promise((resolve, reject) => {
    const h = createHash("sha256");
    createReadStream(path)
      .on("data", (c) => h.update(c))
      .on("end", () => resolve(h.digest("hex")))
      .on("error", reject);
  });
}

/** Where this report was produced, for the export header. */
export async function hostIdentity() {
  const os = await import("node:os");
  return { hostname: os.hostname(), platform: `${os.type()} ${os.release()}`, arch: os.arch() };
}

