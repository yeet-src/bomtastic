"use server";

/* Scan history, on disk. Node's job because the isolate has no
 * filesystem and a history has to outlive a restart.
 *
 * Each scan is saved as one compact JSON snapshot under
 * `.bomtastic/scans/`. The diff itself is computed in the isolate,
 * next to the fresh scan; this module only stores and returns.
 */
import { mkdir, readdir, readFile, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";

const DIR = join(process.cwd(), ".bomtastic", "scans");
const KEEP = 60;

/** Save a snapshot; returns the previous one (or null) so the caller can diff. */
export async function saveScan(snapshot) {
  await mkdir(DIR, { recursive: true });
  const previous = await latestSnapshot();
  const name = `${snapshot.at.replace(/[:.]/g, "-")}.json`;
  await writeFile(join(DIR, name), JSON.stringify(snapshot));

  const files = (await readdir(DIR)).filter((f) => f.endsWith(".json")).sort();
  for (const stale of files.slice(0, Math.max(0, files.length - KEEP))) await unlink(join(DIR, stale)).catch(() => {});

  return { previous, kept: Math.min(files.length, KEEP) };
}

/** The most recent saved snapshot, or null. */
export async function latestSnapshot() {
  try {
    const files = (await readdir(DIR)).filter((f) => f.endsWith(".json")).sort();
    if (!files.length) return null;
    return JSON.parse(await readFile(join(DIR, files[files.length - 1]), "utf8"));
  } catch {
    return null;
  }
}

/** Timestamps of every saved scan, oldest first. */
export async function scanTimes() {
  try {
    return (await readdir(DIR))
      .filter((f) => f.endsWith(".json"))
      .sort()
      .map((f) => f.replace(/\.json$/, "").replace(/^(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})-(\d{3})Z$/, "$1T$2:$3:$4.$5Z"));
  } catch {
    return [];
  }
}
