/* GET /api/sbom — the inventory as CycloneDX 1.5 JSON, so an auditor's
 * tooling can ingest it. Runs in Node, asks the isolate for the latest
 * scan, and stamps the host identity on it.
 */
import { hostIdentity } from "@/lib/enrich.js";
import { latest } from "@/lib/analyst.js";

/* CycloneDX's severity vocabulary; distro feeds say "Important" and
 * "Moderate" where it says high and medium. */
const cdxSeverity = (s) =>
  ({ critical: "critical", important: "high", high: "high", moderate: "medium", medium: "medium", low: "low" })[String(s ?? "").toLowerCase()] ?? "unknown";

export async function GET() {
  const [inv, host] = await Promise.all([latest(), hostIdentity()]);
  if (!inv) return Response.json({ error: "no inventory" }, { status: 503 });

  const component = (row, type) => ({
    "bom-ref": `runtime:${row.path}`,
    type,
    name: row.path.split("/").pop(),
    version: row.package?.split(" ")[1] ?? "unknown",
    group: row.package?.split(" ")[0] ?? undefined,
    purl: row.package ? `pkg:rpm/${row.package.split(" ")[0]}@${row.package.split(" ")[1]}` : undefined,
    hashes: row.sha256 ? [{ alg: "SHA-256", content: row.sha256 }] : undefined,
    properties: [
      { name: "runtime:path", value: row.path },
      { name: "runtime:pids", value: row.pids.join(",") },
      { name: "runtime:processes", value: row.comms.join(",") },
      ...(row.container ? [{ name: "runtime:container", value: row.container }] : []),
      ...(row.package === null && !row.container ? [{ name: "runtime:unpackaged", value: "true" }] : []),
    ],
  });

  const body = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: {
      timestamp: inv.startedAt,
      tools: [{ vendor: "yeet", name: "bomtastic", version: "0.1.0" }],
      component: { type: "device", name: host.hostname, description: `${host.platform} ${host.arch}` },
      properties: Object.entries(inv.counts).map(([k, v]) => ({ name: `runtime:count:${k}`, value: String(v) })),
    },
    components: [
      ...inv.binaries.map((b) => component(b, "application")),
      ...inv.libraries.map((l) => component(l, "library")),
      ...inv.containers.map((c) => ({
        type: "container",
        name: c.name || c.id,
        version: c.image_id?.replace(/^sha256:/, "").slice(0, 12),
        properties: [{ name: "runtime:image", value: c.image ?? "" }, { name: "runtime:state", value: c.state ?? "" }],
      })),
    ],
    /* CycloneDX 1.5 vulnerabilities: one entry per CVE, affecting every
     * component whose package the advisory fixes. */
    vulnerabilities: (inv.vulns?.advisories ?? []).flatMap((a) => {
      const pkgs = new Set(a.packages.map((p) => p.name));
      const affects = [...inv.binaries, ...inv.libraries]
        .filter((r) => r.package && pkgs.has(r.package.split(" ")[0]))
        .map((r) => ({ ref: `runtime:${r.path}` }));
      const entries = a.cves.length ? a.cves : [{ id: a.id, summary: a.title, url: a.url }];
      return entries.map((c) => ({
        id: c.id,
        source: { name: c.id.startsWith("CVE-") ? "OSV" : inv.vulns.source === "dnf" ? "Fedora" : "OSV", url: c.url ?? a.url },
        ratings: c.score != null ? [{ score: c.score, severity: cdxSeverity(c.severity ?? a.severity), method: "CVSSv31", vector: c.vector }] : [{ severity: cdxSeverity(a.severity) }],
        description: c.summary ?? a.title,
        advisories: [{ title: a.id, url: a.url }],
        recommendation: `Update ${a.packages.map((p) => `${p.name} to ${p.fixed ?? "the fixed version"}`).join(", ")} and restart ${(a.processes ?? []).map((p) => p.comm).filter((v, i, arr) => arr.indexOf(v) === i).join(", ") || "the affected processes"}.`,
        affects,
      }));
    }),
    /* Not part of CycloneDX proper; a consumer that does not know the
     * key ignores it, and one that does gets the findings. */
    "x-runtime-findings": inv.findings,
  };

  return new Response(JSON.stringify(body, null, 2), {
    headers: { "content-type": "application/vnd.cyclonedx+json", "content-disposition": `inline; filename="${host.hostname}-bomtastic.json"` },
  });
}
