// Bundle the scan Worker so it can sit next to the isolate entry as one
// file. `yeet:*` stays external (the runtime provides it); everything
// else is inlined. Run before build and dev.
import { createRequire } from "node:module";
import { mkdir, copyFile } from "node:fs/promises";

const esbuild = createRequire(new URL("../node_modules/yeetkit/package.json", import.meta.url))("esbuild");
await mkdir("public", { recursive: true });
await esbuild.build({
  entryPoints: ["app/lib/scan-worker.js"],
  bundle: true,
  format: "esm",
  platform: "neutral",
  external: ["yeet:*"],
  outfile: "public/scan-worker.js",
  logLevel: "warning",
});
// dev mode runs the isolate from .yeetkit/, and a Worker resolves its
// script relative to that entry.
await mkdir(".yeetkit", { recursive: true });
await copyFile("public/scan-worker.js", ".yeetkit/scan-worker.js");
console.log("worker → public/scan-worker.js (+ .yeetkit/)");
