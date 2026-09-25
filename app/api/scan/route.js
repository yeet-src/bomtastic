/* POST /api/scan — run a scan now. For cron, CI, or a webhook: the
 * response is the new counts plus what changed since the previous
 * scan, which is the part a scheduled run exists to notice. */
import { rescan } from "@/lib/analyst.js";

export async function POST() {
  const result = await rescan();
  if (!result) return Response.json({ error: "scan failed" }, { status: 500 });
  return Response.json(result);
}

export async function GET() {
  return Response.json({ hint: "POST to run a scan; GET /api/sbom for the inventory" }, { status: 405, headers: { allow: "POST" } });
}
