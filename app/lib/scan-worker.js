/* Entry of the scan Worker. Bundled by scripts/worker.mjs into
 * public/scan-worker.js, which the build copies next to dist/server.js.
 * Runs the walk as soon as the opener constructs it and posts progress
 * lines, then the result.
 *
 * A message is capped at 124 KiB by the runtime and a walk of a few
 * hundred processes is a couple hundred KB of JSON, so the result goes
 * back as a sequence of string chunks the opener joins and parses. The
 * cap counts the serialized string, which is two bytes per character
 * once any non-Latin-1 character is in it (one emoji in one process's
 * argv is enough), so a chunk is 60,000 characters: 120,000 bytes at
 * worst, under the cap either way. */
import { walk } from "./walk.js";

const CHUNK = 60_000;

try {
  const result = await walk((progress) => postMessage({ progress }));
  const text = JSON.stringify(result);
  const total = Math.ceil(text.length / CHUNK);
  for (let i = 0; i < total; i++) postMessage({ chunk: text.slice(i * CHUNK, (i + 1) * CHUNK), index: i, total });
} catch (error) {
  postMessage({ error: String(error?.message ?? error) });
}
