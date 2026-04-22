#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import fetch from "node-fetch";
import https from "https";

const BD_URL = process.env.BLACKDUCK_URL;
const BD_TOKEN = process.env.BLACKDUCK_TOKEN;

const log = (...args) => process.stderr.write("[blackduck-mcp] " + args.join(" ") + "\n");

log("Starting BlackDuck MCP server...");
log("BD_URL:", BD_URL);
log("BD_TOKEN:", BD_TOKEN ? `set (${BD_TOKEN.length} chars)` : "NOT SET");

const httpsAgent = new https.Agent({ rejectUnauthorized: false });

// ── Accept header constants — every endpoint has its own versioned media type
const ACCEPT = {
  project:      "application/vnd.blackducksoftware.project-detail-4+json",
  version:      "application/vnd.blackducksoftware.project-detail-5+json",
  bom:          "application/vnd.blackducksoftware.bill-of-materials-6+json",
  policy:       "application/vnd.blackducksoftware.policy-status-4+json",
  component:    "application/vnd.blackducksoftware.component-detail-5+json",
  vulnerability:"application/vnd.blackducksoftware.vulnerability-4+json",
  report:       "application/vnd.blackducksoftware.report-4+json",
  codeLocation: "application/vnd.blackducksoftware.scan-5+json",
  license:      "application/vnd.blackducksoftware.bdio-2+json",
  user:         "application/vnd.blackducksoftware.user-4+json",
  summary:      "application/vnd.blackducksoftware.project-detail-4+json",
};

// ── Extract UUID from HATEOAS href
// e.g. https://blackduck.../api/projects/abc-123  →  abc-123
function extractId(href) {
  return href?.split("/").pop();
}

// ── Fetch with 30s timeout
async function fetchWithTimeout(url, options = {}, timeoutMs = 30000) {
  const controller = new AbortController();
  const timer = setTimeout(() => {
    log(`TIMEOUT after ${timeoutMs}ms — ${url}`);
    controller.abort();
  }, timeoutMs);
  try {
    log(`--> ${options.method ?? "GET"} ${url}`);
    const res = await fetch(url, { ...options, signal: controller.signal, agent: httpsAgent });
    log(`<-- ${res.status} ${res.statusText}`);
    return res;
  } catch (err) {
    log(`FETCH ERROR: ${err.message}`);
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

// ── Auth: exchange API token for short-lived Bearer JWT
async function getBearerToken() {
  const res = await fetchWithTimeout(`${BD_URL}/api/tokens/authenticate`, {
    method: "POST",
    headers: {
      Authorization: `token ${BD_TOKEN}`,
      Accept: ACCEPT.user,
      "Content-Type": "application/json",
    },
  });
  const raw = await res.text();
  if (raw.trim().startsWith("<!") || raw.toLowerCase().includes("<html")) {
    throw new Error("BlackDuck returned HTML — Okta intercepted. Check your API token.");
  }
  if (!res.ok) throw new Error(`Auth failed ${res.status}: ${raw}`);
  const data = JSON.parse(raw);
  if (!data.bearerToken) throw new Error(`No bearerToken in response: ${raw}`);
  log("Auth OK — bearer token acquired");
  return data.bearerToken;
}

// ── Core fetch helper — resolves full or relative URLs
async function bdFetch(path, accept) {
  const bearer = await getBearerToken();
  const url = path.startsWith("http") ? path : `${BD_URL}${path}`;
  const res = await fetchWithTimeout(url, {
    headers: {
      Authorization: `Bearer ${bearer}`,
      Accept: accept,
      "Content-Type": "application/json",
    },
  });
  const raw = await res.text();
  log(`Body preview: ${raw.slice(0, 200)}`);
  if (!res.ok) throw new Error(`API error ${res.status} for ${path}: ${raw}`);
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error(`Response not JSON for ${path}: ${raw.slice(0, 300)}`);
  }
}

// ── Paginate through all items automatically
async function bdFetchAll(path, accept) {
  let offset = 0;
  const limit = 100;
  let all = [];
  while (true) {
    const sep = path.includes("?") ? "&" : "?";
    const data = await bdFetch(`${path}${sep}limit=${limit}&offset=${offset}`, accept);
    const items = data.items ?? [];
    all = all.concat(items);
    log(`Paginated: got ${items.length}, total so far ${all.length} / ${data.totalCount}`);
    if (all.length >= (data.totalCount ?? items.length) || items.length === 0) break;
    offset += limit;
  }
  return all;
}

// ════════════════════════════════════════════════════════════
// MCP TOOLS
// ════════════════════════════════════════════════════════════

const server = new McpServer({ name: "blackduck", version: "1.0.0" });

// ────────────────────────────────────────────────
// USE CASE 1: List all projects
// ────────────────────────────────────────────────
server.tool("list_projects", "List all BlackDuck projects", {}, async () => {
  const items = await bdFetchAll("/api/projects", ACCEPT.project);
  const result = items.map(p => ({
    name: p.name,
    projectId: extractId(p._meta?.href),
    description: p.description,
    createdAt: p.createdAt,
  }));
  return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
});

// ────────────────────────────────────────────────
// USE CASE 2: Get versions for a project
// ────────────────────────────────────────────────
server.tool(
  "get_project_versions",
  "Get all versions for a BlackDuck project sorted latest first",
  { projectId: z.string().describe("UUID from list_projects") },
  async ({ projectId }) => {
    const data = await bdFetch(
      `/api/projects/${projectId}/versions?limit=20&sort=createdAt%20DESC`,
      ACCEPT.version
    );
    const result = (data.items ?? []).map(v => ({
      versionName: v.versionName,
      versionId: extractId(v._meta?.href),
      phase: v.phase,
      distribution: v.distribution,
      createdAt: v.createdAt,
      settingUpdatedAt: v.settingUpdatedAt,
    }));
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ────────────────────────────────────────────────
// USE CASE 3: Get BOM components (all pages)
// ────────────────────────────────────────────────
server.tool(
  "get_bom_components",
  "Get all BOM components for a project version",
  {
    projectId: z.string(),
    versionId: z.string(),
  },
  async ({ projectId, versionId }) => {
    log(`Fetching BOM: project=${projectId} version=${versionId}`);
    const items = await bdFetchAll(
      `/api/projects/${projectId}/versions/${versionId}/components`,
      ACCEPT.bom
    );
    const result = items.map(c => ({
      componentName: c.componentName,
      componentVersionName: c.componentVersionName,
      componentId: extractId(c.component),
      componentVersionId: extractId(c.componentVersion),
      usages: c.usages,
      reviewStatus: c.reviewStatus,
      policyStatus: c.policyStatus,
      licenses: c.licenses?.map(l => l.licenseDisplay),
      securityRiskProfile: c.securityRiskProfile,
      licenseRiskProfile: c.licenseRiskProfile,
      operationalRiskProfile: c.operationalRiskProfile,
    }));
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ────────────────────────────────────────────────
// USE CASE 4: Get policy violations only
// ────────────────────────────────────────────────
server.tool(
  "get_policy_violations",
  "Get policy violations for a project version",
  {
    projectId: z.string(),
    versionId: z.string(),
  },
  async ({ projectId, versionId }) => {
    log(`Fetching policy: project=${projectId} version=${versionId}`);

    // Overall status
    const status = await bdFetch(
      `/api/projects/${projectId}/versions/${versionId}/policy-status`,
      ACCEPT.policy
    );

    // Only components IN_VIOLATION
    const violated = await bdFetchAll(
      `/api/projects/${projectId}/versions/${versionId}/components?filter=policyStatus%3AIN_VIOLATION`,
      ACCEPT.bom
    );

    return {
      content: [{
        type: "text", text: JSON.stringify({
          overallStatus: status.overallStatus,
          policyViolationDetails: status.componentVersionPolicyViolationDetails,
          violatingComponents: violated.map(c => ({
            componentName: c.componentName,
            version: c.componentVersionName,
            policyStatus: c.policyStatus,
            approvalStatus: c.approvalStatus,
            licenses: c.licenses?.map(l => l.licenseDisplay),
          })),
        }, null, 2)
      }]
    };
  }
);

// ────────────────────────────────────────────────
// USE CASE 5: Get vulnerabilities for a component
// ────────────────────────────────────────────────
server.tool(
  "get_component_vulnerabilities",
  "Get CVEs and vulnerabilities for a specific component version",
  {
    projectId: z.string(),
    versionId: z.string(),
    componentId: z.string().describe("componentId from get_bom_components"),
    componentVersionId: z.string().describe("componentVersionId from get_bom_components"),
  },
  async ({ projectId, versionId, componentId, componentVersionId }) => {
    log(`Fetching vulnerabilities for component=${componentId} version=${componentVersionId}`);
    const items = await bdFetchAll(
      `/api/projects/${projectId}/versions/${versionId}/components/${componentId}/versions/${componentVersionId}/vulnerabilities`,
      ACCEPT.vulnerability
    );
    const result = items.map(v => ({
      vulnerabilityName: v.name,
      description: v.description,
      severity: v.severity,
      cvss2Score: v.cvss2?.baseScore,
      cvss3Score: v.cvss3?.baseScore,
      publishedDate: v.publishedDate,
      updatedDate: v.updatedDate,
      remediationStatus: v.remediationStatus,
      solution: v.solution,
    }));
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ────────────────────────────────────────────────
// USE CASE 6: Search components by CVE ID
// ────────────────────────────────────────────────
server.tool(
  "search_by_cve",
  "Find which BOM components in a project version are affected by a specific CVE",
  {
    projectId: z.string(),
    versionId: z.string(),
    cveId: z.string().describe("CVE ID e.g. CVE-2021-44228"),
  },
  async ({ projectId, versionId, cveId }) => {
    log(`Searching for CVE: ${cveId}`);
    const allComponents = await bdFetchAll(
      `/api/projects/${projectId}/versions/${versionId}/components`,
      ACCEPT.bom
    );

    const affected = [];
    for (const c of allComponents) {
      const cId = extractId(c.component);
      const cvId = extractId(c.componentVersion);
      if (!cId || !cvId) continue;

      try {
        const vulns = await bdFetchAll(
          `/api/projects/${projectId}/versions/${versionId}/components/${cId}/versions/${cvId}/vulnerabilities`,
          ACCEPT.vulnerability
        );
        const match = vulns.filter(v => v.name?.toUpperCase() === cveId.toUpperCase());
        if (match.length > 0) {
          affected.push({
            componentName: c.componentName,
            componentVersion: c.componentVersionName,
            cve: cveId,
            severity: match[0].severity,
            cvss3Score: match[0].cvss3?.baseScore,
            remediationStatus: match[0].remediationStatus,
          });
        }
      } catch (e) {
        log(`Skipping vuln fetch for ${c.componentName}: ${e.message}`);
      }
    }

    return {
      content: [{
        type: "text", text: JSON.stringify({
          cve: cveId,
          affectedComponents: affected,
          totalAffected: affected.length,
        }, null, 2)
      }]
    };
  }
);

// ────────────────────────────────────────────────
// USE CASE 7: Get license risks
// ────────────────────────────────────────────────
server.tool(
  "get_license_risks",
  "Get all components with HIGH or CRITICAL license risk in a project version",
  {
    projectId: z.string(),
    versionId: z.string(),
  },
  async ({ projectId, versionId }) => {
    const items = await bdFetchAll(
      `/api/projects/${projectId}/versions/${versionId}/components`,
      ACCEPT.bom
    );
    const risky = items
      .filter(c => {
        const counts = c.licenseRiskProfile?.counts ?? [];
        const high = counts.find(x => x.countType === "HIGH")?.count ?? 0;
        const critical = counts.find(x => x.countType === "CRITICAL")?.count ?? 0;
        return high > 0 || critical > 0;
      })
      .map(c => ({
        componentName: c.componentName,
        version: c.componentVersionName,
        licenseRisk: c.licenseRiskProfile?.counts,
        licenses: c.licenses?.map(l => l.licenseDisplay),
        reviewStatus: c.reviewStatus,
      }));
    return {
      content: [{
        type: "text", text: JSON.stringify({
          totalRiskyComponents: risky.length,
          components: risky,
        }, null, 2)
      }]
    };
  }
);

// ────────────────────────────────────────────────
// USE CASE 8: Get scan / code location status
// ────────────────────────────────────────────────
server.tool(
  "get_scan_status",
  "Get latest scan results and code location status for a project version",
  {
    projectId: z.string(),
    versionId: z.string(),
  },
  async ({ projectId, versionId }) => {
    const data = await bdFetch(
      `/api/projects/${projectId}/versions/${versionId}/codelocations`,
      ACCEPT.codeLocation
    );
    const result = (data.items ?? []).map(s => ({
      name: s.name,
      scanType: s.type,
      createdAt: s.createdAt,
      updatedAt: s.updatedAt,
      mappedProjectVersion: s.mappedProjectVersion,
    }));
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ────────────────────────────────────────────────
// USE CASE 9: Get risk summary for a version
// ────────────────────────────────────────────────
server.tool(
  "get_risk_summary",
  "Get security, license and operational risk summary counts for a project version",
  {
    projectId: z.string(),
    versionId: z.string(),
  },
  async ({ projectId, versionId }) => {
    const data = await bdFetch(
      `/api/projects/${projectId}/versions/${versionId}`,
      ACCEPT.version
    );
    return {
      content: [{
        type: "text", text: JSON.stringify({
          versionName: data.versionName,
          phase: data.phase,
          securityRiskProfile: data.securityRiskProfile,
          licenseRiskProfile: data.licenseRiskProfile,
          operationalRiskProfile: data.operationalRiskProfile,
          policyStatus: data.policyStatus,
        }, null, 2)
      }]
    };
  }
);

// ────────────────────────────────────────────────
// USE CASE 10: ONE-SHOT — full findings for a project
// ────────────────────────────────────────────────
server.tool(
  "get_findings_for_project",
  "One-shot: find project by name, get latest version, return all violations + risk summary",
  { projectName: z.string().describe("Partial or full project name e.g. vmui") },
  async ({ projectName }) => {
    log(`One-shot findings for: ${projectName}`);

    // 1. Find project
    const projects = await bdFetch(
      `/api/projects?q=name%3A${encodeURIComponent(projectName)}&limit=10`,
      ACCEPT.project
    );
    const project = projects.items?.[0];
    if (!project) throw new Error(`No project found matching: ${projectName}`);
    const projectId = extractId(project._meta?.href);
    log(`Project: ${project.name} (${projectId})`);

    // 2. Latest version
    const versions = await bdFetch(
      `/api/projects/${projectId}/versions?limit=5&sort=createdAt%20DESC`,
      ACCEPT.version
    );
    const latest = versions.items?.[0];
    if (!latest) throw new Error(`No versions found for: ${project.name}`);
    const versionId = extractId(latest._meta?.href);
    log(`Latest version: ${latest.versionName} (${versionId})`);

    // 3. Risk summary (single lightweight call)
    const riskSummary = {
      security: latest.securityRiskProfile,
      license: latest.licenseRiskProfile,
      operational: latest.operationalRiskProfile,
    };

    // 4. Overall policy status
    const policyStatus = await bdFetch(
      `/api/projects/${projectId}/versions/${versionId}/policy-status`,
      ACCEPT.policy
    );

    // 5. Violating components only
    const violated = await bdFetchAll(
      `/api/projects/${projectId}/versions/${versionId}/components?filter=policyStatus%3AIN_VIOLATION`,
      ACCEPT.bom
    );

    // 6. Components with CRITICAL/HIGH security risk
    const allComponents = await bdFetchAll(
      `/api/projects/${projectId}/versions/${versionId}/components`,
      ACCEPT.bom
    );
    const securityRisky = allComponents.filter(c => {
      const counts = c.securityRiskProfile?.counts ?? [];
      const critical = counts.find(x => x.countType === "CRITICAL")?.count ?? 0;
      const high = counts.find(x => x.countType === "HIGH")?.count ?? 0;
      return critical > 0 || high > 0;
    }).map(c => ({
      componentName: c.componentName,
      version: c.componentVersionName,
      securityRisk: c.securityRiskProfile?.counts,
      policyStatus: c.policyStatus,
    }));

    return {
      content: [{
        type: "text", text: JSON.stringify({
          project: project.name,
          version: latest.versionName,
          projectId,
          versionId,
          riskSummary,
          overallPolicyStatus: policyStatus.overallStatus,
          policyViolationDetails: policyStatus.componentVersionPolicyViolationDetails,
          violatingComponents: violated.map(c => ({
            componentName: c.componentName,
            version: c.componentVersionName,
            policyStatus: c.policyStatus,
            licenses: c.licenses?.map(l => l.licenseDisplay),
          })),
          securityRiskyComponents: securityRisky,
          totalViolating: violated.length,
          totalSecurityRisky: securityRisky.length,
          totalBomComponents: allComponents.length,
        }, null, 2)
      }]
    };
  }
);

// ── Startup check
getBearerToken()
  .then(() => log("Startup check PASSED — BlackDuck reachable and token valid"))
  .catch(err => log("Startup check FAILED —", err.message));

const transport = new StdioServerTransport();
await server.connect(transport);