// One-off helper to switch the blackduck MCP entry from npx-based to local
// file launch. Safe to re-run: it's a no-op if the expected source snippet
// isn't found. Delete this file after use.
const fs = require("fs");
const p = "C:/Users/rsabde/.codeium/windsurf/mcp_config.json";

const CR = "\r\n";
const before = [
  '        "blackduck": {',
  '            "command": "npx",',
  '            "args": [',
  '                "-y",',
  '                "C:/Users/rsabde/blackduck-mcp/index.js"',
  '            ],',
].join(CR);
const after = [
  '        "blackduck": {',
  '            "command": "node",',
  '            "args": [',
  '                "C:/Users/rsabde/blackduck-mcp/index.js"',
  '            ],',
].join(CR);

let s = fs.readFileSync(p, "utf8");
if (!s.includes(before)) {
  console.log("NO MATCH - config may already be patched or has drifted");
  process.exit(2);
}
s = s.replace(before, after);
fs.writeFileSync(p, s);
console.log("OK - mcp_config.json blackduck entry now launches local node");
