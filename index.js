import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import fetch from "node-fetch";
import https from "https";

const BD_URL = process.env.BLACKDUCK_URL;
const BD_TOKEN = process.env.BLACKDUCK_TOKEN;

// All debug logs MUST go to stderr — stdout is reserved for MCP protocol
const log = (...args) => process.stderr.write("[blackduck-mcp] " + args.join(" ") + "\n");

log("Starting BlackDuck MCP server...");
log("BD_URL:", BD_URL);
log("BD_TOKEN:", BD_TOKEN ? `set (${BD_TOKEN.length} chars)` : "NOT SET");

const httpsAgent = new https.Agent({ rejectUnauthorized: false });

// Fetch with timeout so it never hangs silently
async function fetchWithTimeout(url, options = {}, timeoutMs = 15000) {
  const controller = new AbortController();
  const timer = setTimeout(() => {
    log(`TIMEOUT after ${timeoutMs}ms for: ${url}`);
    controller.abort();
  }, timeoutMs);

  try {
    log(`--> ${options.method ?? "GET"} ${url}`);
    const res = await fetch(url, { ...options, signal: controller.signal, agent: httpsAgent });
    log(`<-- ${res.status} ${res.statusText} from ${url}`);
    return res;
  } catch (err) {
    log(`FETCH ERROR for ${url}:`, err.message);
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

async function getBearerToken() {
  log("Authenticating with BlackDuck...");

  const res = await fetchWithTimeout(`${BD_URL}/api/tokens/authenticate`, {
    method: "POST",
    headers: {
      Authorization: `token ${BD_TOKEN}`,
      Accept: "application/vnd.blackducksoftware.user-4+json",
      "Content-Type": "application/json",
    },
  });

  const rawText = await res.text();
  log("Auth raw response (first 300 chars):", rawText.slice(0, 300));

  // Okta redirect detection — if BlackDuck returns HTML it means Okta intercepted
  if (rawText.trim().startsWith("<!") || rawText.toLowerCase().includes("<html")) {
    throw new Error(
      "BlackDuck returned an HTML page instead of JSON. " +
      "This usually means Okta intercepted the request. " +
      "Make sure your BLACKDUCK_TOKEN is a valid API token generated from " +
      "BlackDuck Profile > User Tokens (not your Okta password)."
    );
  }

  if (!res.ok) {
    throw new Error(`Auth failed: HTTP ${res.status} — ${rawText}`);
  }

  let data;
  try {
    data = JSON.parse(rawText);
  } catch {
    throw new Error(`Auth response was not valid JSON: ${rawText.slice(0, 200)}`);
  }

  if (!data.bearerToken) {
    throw new Error(`Auth succeeded but no bearerToken in response: ${JSON.stringify(data)}`);
  }

  log("Auth successful — got bearer token");
  return data.bearerToken;
}

async function bdFetch(path, acceptHeader) {
  const bearer = await getBearerToken();

  const res = await fetchWithTimeout(`${BD_URL}${path}`, {
    headers: {
      Authorization: `Bearer ${bearer}`,
      Accept: acceptHeader ?? "application/vnd.blackducksoftware.project-detail-4+json",
      "Content-Type": "application/json",
    },
  });

  const rawText = await res.text();
  log(`Response body for ${path} (first 200 chars):`, rawText.slice(0, 200));

  if (!res.ok) {
    throw new Error(`API error ${res.status} for ${path}: ${rawText}`);
  }

  return JSON.parse(rawText);
}

// ── MCP Tools
const server = new McpServer({ name: "blackduck", version: "1.0.0" });

server.tool("list_projects", "List all BlackDuck projects", {}, async () => {
  const data = await bdFetch("/api/projects?limit=50");
  return { content: [{ type: "text", text: JSON.stringify(data.items, null, 2) }] };
});

server.tool(
  "get_project_versions",
  "Get versions for a BlackDuck project",
  { projectId: z.string().describe("The BlackDuck project ID") },
  async ({ projectId }) => {
    const data = await bdFetch(`/api/projects/${projectId}/versions`);
    return { content: [{ type: "text", text: JSON.stringify(data.items, null, 2) }] };
  }
);

server.tool(
  "get_bom_components",
  "Get BOM components for a project version",
  { projectId: z.string(), versionId: z.string() },
  async ({ projectId, versionId }) => {
    const data = await bdFetch(
      `/api/projects/${projectId}/versions/${versionId}/components?limit=100`
    );
    return { content: [{ type: "text", text: JSON.stringify(data.items, null, 2) }] };
  }
);

server.tool(
  "get_policy_violations",
  "Get policy violations for a project version",
  { projectId: z.string(), versionId: z.string() },
  async ({ projectId, versionId }) => {
    const data = await bdFetch(
      `/api/projects/${projectId}/versions/${versionId}/policy-status`,
      "application/vnd.blackducksoftware.policy-status-4+json"
    );
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

// ── Startup connectivity check — runs before MCP handshake
log("Running startup auth check...");
getBearerToken()
  .then(() => log("Startup check PASSED — BlackDuck is reachable and token is valid"))
  .catch(err => log("Startup check FAILED —", err.message));

const transport = new StdioServerTransport();
await server.connect(transport);