import { displayPath, stableHash } from "./fingerprint.js";
import { redactEnv } from "./redact.js";

export function generateTextReport(result) {
  const lines = [];
  lines.push("mcp-guard scan report");
  lines.push(`Generated: ${result.metadata.generatedAt}`);
  lines.push(`Scanned files: ${result.summary.scannedFileCount}`);
  lines.push(`MCP servers: ${result.summary.serverCount}`);
  lines.push(`Active findings: ${result.summary.findingCount}`);
  if (hasBaseline(result)) {
    lines.push(`Accepted by baseline: ${result.summary.acceptedFindingCount}`);
    lines.push(`Total observed findings: ${result.summary.totalFindingCount}`);
  }
  if (hasPolicy(result)) {
    lines.push(`Policy: ${displayPath(result.policy.path, result.metadata.cwd)}`);
  }
  lines.push(`Risk score: ${result.summary.riskScore}`);
  lines.push(`Critical: ${result.summary.counts.critical}  High: ${result.summary.counts.high}  Medium: ${result.summary.counts.medium}  Low: ${result.summary.counts.low}`);
  lines.push("");

  if (result.scannedFiles.length > 0) {
    lines.push("Scanned config files:");
    for (const file of result.scannedFiles) {
      lines.push(`- ${displayPath(file, result.metadata.cwd)}`);
    }
    lines.push("");
  }

  if (result.findings.length === 0) {
    lines.push("No active findings.");
  } else {
    lines.push("Active findings:");
    for (const finding of result.findings) {
      lines.push(`- [${finding.severity.toUpperCase()}] ${finding.id} ${finding.title}`);
      lines.push(`  Server: ${finding.serverName}`);
      lines.push(`  Evidence: ${finding.evidence}`);
      lines.push(`  Fingerprint: ${finding.fingerprint}`);
      lines.push(`  Fix: ${finding.recommendation}`);
    }
  }

  if (hasAcceptedFindings(result)) {
    lines.push("");
    lines.push("Accepted by baseline:");
    for (const finding of result.acceptedFindings) {
      lines.push(`- [${finding.severity.toUpperCase()}] ${finding.id} ${finding.title}`);
      lines.push(`  Server: ${finding.serverName}`);
      lines.push(`  Fingerprint: ${finding.fingerprint}`);
      if (finding.acceptedReason) {
        lines.push(`  Reason: ${finding.acceptedReason}`);
      }
    }
  }

  return `${lines.join("\n")}\n`;
}

export function generateMarkdownReport(result) {
  const lines = [];
  lines.push("# mcp-guard Scan Report");
  lines.push("");
  lines.push(`Generated: ${result.metadata.generatedAt}`);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push(`- Scanned files: ${result.summary.scannedFileCount}`);
  lines.push(`- MCP servers: ${result.summary.serverCount}`);
  lines.push(`- Active findings: ${result.summary.findingCount}`);
  if (hasBaseline(result)) {
    lines.push(`- Accepted by baseline: ${result.summary.acceptedFindingCount}`);
    lines.push(`- Total observed findings: ${result.summary.totalFindingCount}`);
    lines.push(`- Baseline: \`${result.baseline.path || "enabled"}\``);
  }
  if (hasPolicy(result)) {
    lines.push(`- Policy: \`${displayPath(result.policy.path, result.metadata.cwd)}\``);
  }
  lines.push(`- Risk score: ${result.summary.riskScore}`);
  lines.push(`- Critical: ${result.summary.counts.critical}`);
  lines.push(`- High: ${result.summary.counts.high}`);
  lines.push(`- Medium: ${result.summary.counts.medium}`);
  lines.push(`- Low: ${result.summary.counts.low}`);
  lines.push("");

  lines.push("## Scanned Files");
  lines.push("");
  if (result.scannedFiles.length === 0) {
    lines.push("- None found");
  } else {
    for (const file of result.scannedFiles) {
      lines.push(`- \`${displayPath(file, result.metadata.cwd)}\``);
    }
  }
  lines.push("");

  if (hasPolicy(result)) {
    lines.push("## Policy");
    lines.push("");
    lines.push(`- Path: \`${displayPath(result.policy.path, result.metadata.cwd)}\``);
    lines.push(`- Allowed commands: ${inlineList(result.policy.allowedCommands)}`);
    lines.push(`- Allowed packages: ${inlineList(result.policy.allowedPackages)}`);
    lines.push(`- Allowed directories: ${inlineList(result.policy.allowedDirectories)}`);
    lines.push(`- Allowed remote URLs: ${inlineList(result.policy.allowedRemoteUrls)}`);
    lines.push("");
  }

  lines.push("## MCP Server Inventory");
  lines.push("");
  if (result.servers.length === 0) {
    lines.push("- No MCP servers found.");
  } else {
    lines.push("| Server | Command | Args | CWD | URL | Env file | Env |");
    lines.push("| --- | --- | --- | --- | --- | --- | --- |");
    for (const server of result.servers) {
      const env = Object.entries(redactEnv(server.env)).map(([key, value]) => `${key}=${value}`).join("<br>");
      lines.push(`| ${cell(server.name)} | ${cell(server.command || "-")} | ${cell(server.args.join(" ") || "-")} | ${cell(server.cwd || "-")} | ${cell(server.url || "-")} | ${cell(server.envFile || "-")} | ${cell(env || "-")} |`);
    }
  }
  lines.push("");

  lines.push("## Active Findings");
  lines.push("");
  if (result.findings.length === 0) {
    lines.push("No active findings.");
  } else {
    lines.push("| Severity | Rule | Server | Finding | Evidence | Fingerprint | Recommendation |");
    lines.push("| --- | --- | --- | --- | --- | --- | --- |");
    for (const finding of result.findings) {
      lines.push(`| ${cell(finding.severity)} | ${cell(finding.id)} | ${cell(finding.serverName)} | ${cell(finding.title)} | ${cell(finding.evidence)} | ${cell(finding.fingerprint)} | ${cell(finding.recommendation)} |`);
    }
  }
  lines.push("");

  if (hasBaseline(result)) {
    lines.push("## Accepted Baseline Findings");
    lines.push("");
    if (!hasAcceptedFindings(result)) {
      lines.push("No current findings matched the baseline.");
    } else {
      lines.push("| Severity | Rule | Server | Finding | Fingerprint | Reason |");
      lines.push("| --- | --- | --- | --- | --- | --- |");
      for (const finding of result.acceptedFindings) {
        lines.push(`| ${cell(finding.severity)} | ${cell(finding.id)} | ${cell(finding.serverName)} | ${cell(finding.title)} | ${cell(finding.fingerprint)} | ${cell(finding.acceptedReason || "-")} |`);
      }
    }
    lines.push("");
  }

  lines.push("## Notes");
  lines.push("");
  lines.push("- This report is an assistive security review, not a guarantee that all issues were found.");
  lines.push("- Secret-like values are redacted by default.");
  lines.push("- Review each MCP server before granting access to files, shells, SaaS accounts, or production systems.");

  return `${lines.join("\n")}\n`;
}

export function generateJsonReport(result) {
  return JSON.stringify(sanitizeResult(result), null, 2);
}

export function generateSarifReport(result) {
  const rules = buildSarifRules(result.findings);
  const sarif = {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-guard",
            informationUri: "https://github.com/ChaoYue0307/mcp-guard",
            semanticVersion: result.metadata.toolVersion,
            rules
          }
        },
        automationDetails: {
          id: "mcp-guard/"
        },
        invocations: [
          {
            executionSuccessful: true,
            workingDirectory: {
              uri: uriFromPath(result.metadata.cwd, result.metadata.cwd)
            }
          }
        ],
        results: result.findings.map((finding) => sarifResult(finding, result.metadata.cwd))
      }
    ]
  };

  return JSON.stringify(sarif, null, 2);
}

export function generateHtmlReport(result) {
  const safeResult = sanitizeResult(result);
  const riskTone = riskToneForScore(safeResult.summary.riskScore);
  const findings = safeResult.findings;
  const acceptedFindings = safeResult.acceptedFindings || [];
  const servers = safeResult.servers;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>mcp-guard Scan Report</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f8fafc;
      --panel: #ffffff;
      --ink: #111827;
      --muted: #5b6575;
      --line: #d9e2ec;
      --soft: #eef4f7;
      --critical: #b91c1c;
      --high: #c2410c;
      --medium: #a16207;
      --low: #0f766e;
      --info: #1d4ed8;
      --shadow: 0 20px 55px rgba(15, 23, 42, 0.08);
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }

    main {
      width: min(1120px, calc(100% - 32px));
      margin: 0 auto;
      padding: 28px 0 48px;
    }

    .hero {
      background: #ffffff;
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      padding: 28px;
      display: grid;
      grid-template-columns: minmax(0, 1fr) 240px;
      gap: 24px;
      align-items: stretch;
    }

    .eyebrow {
      margin: 0 0 8px;
      color: var(--info);
      font-size: 13px;
      font-weight: 700;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    h1, h2 {
      letter-spacing: 0;
      line-height: 1.08;
    }

    h1 {
      margin: 0;
      font-size: 34px;
    }

    h2 {
      margin: 0 0 14px;
      font-size: 21px;
    }

    .lead {
      max-width: 720px;
      margin: 12px 0 0;
      color: var(--muted);
      font-size: 16px;
    }

    .scorecard {
      border-radius: 8px;
      border: 1px solid var(--line);
      background: var(--soft);
      padding: 18px;
      min-height: 176px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }

    .score-label {
      margin: 0;
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
    }

    .score-value {
      margin: 8px 0;
      font-size: 58px;
      font-weight: 800;
      line-height: 1;
      color: var(--${riskTone});
    }

    .score-caption {
      margin: 0;
      color: var(--muted);
      font-size: 14px;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      margin: 18px 0 0;
    }

    .metric {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
    }

    .metric strong {
      display: block;
      font-size: 24px;
      line-height: 1.1;
    }

    .metric span {
      display: block;
      margin-top: 6px;
      color: var(--muted);
      font-size: 13px;
    }

    section {
      margin-top: 22px;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 10px 30px rgba(15, 23, 42, 0.04);
      padding: 22px;
    }

    .severity-row {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
    }

    .severity {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      min-height: 78px;
    }

    .severity b {
      display: block;
      font-size: 22px;
      line-height: 1.1;
    }

    .severity span {
      display: block;
      margin-top: 6px;
      color: var(--muted);
      font-size: 13px;
      text-transform: capitalize;
    }

    .critical { color: var(--critical); }
    .high { color: var(--high); }
    .medium { color: var(--medium); }
    .low { color: var(--low); }

    .table-wrap {
      width: 100%;
      overflow-x: auto;
      border: 1px solid var(--line);
      border-radius: 8px;
    }

    table {
      width: 100%;
      min-width: 760px;
      border-collapse: collapse;
      background: var(--panel);
    }

    th, td {
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
      font-size: 14px;
    }

    th {
      color: #374151;
      background: #f1f5f9;
      font-size: 12px;
      text-transform: uppercase;
    }

    tr:last-child td { border-bottom: 0; }

    code {
      padding: 2px 5px;
      border-radius: 5px;
      background: #eef2f7;
      color: #111827;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      font-size: 0.92em;
      white-space: normal;
      overflow-wrap: anywhere;
    }

    .pill {
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      padding: 3px 8px;
      border-radius: 999px;
      background: #f1f5f9;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }

    .pill.critical { background: #fee2e2; }
    .pill.high { background: #ffedd5; }
    .pill.medium { background: #fef3c7; }
    .pill.low { background: #ccfbf1; }

    .empty {
      margin: 0;
      color: var(--muted);
      border: 1px dashed var(--line);
      border-radius: 8px;
      padding: 16px;
      background: #fbfdff;
    }

    .notes {
      color: var(--muted);
      font-size: 14px;
    }

    .notes ul {
      margin: 10px 0 0;
      padding-left: 18px;
    }

    @media (max-width: 780px) {
      main {
        width: min(100% - 20px, 1120px);
        padding-top: 10px;
      }

      .hero {
        grid-template-columns: 1fr;
        padding: 20px;
      }

      h1 { font-size: 28px; }

      .grid,
      .severity-row {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
    }

    @media (max-width: 460px) {
      .grid,
      .severity-row {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <main>
    <header class="hero">
      <div>
        <p class="eyebrow">mcp-guard scan report</p>
        <h1>AI agent tool risk review</h1>
        <p class="lead">Local-first review of MCP server configuration, startup commands, remote endpoints, filesystem scope, and secret-like values.</p>
        <div class="grid">
          ${metric("Scanned files", safeResult.summary.scannedFileCount)}
          ${metric("MCP servers", safeResult.summary.serverCount)}
          ${metric("Active findings", safeResult.summary.findingCount)}
          ${metric(hasBaseline(safeResult) ? "Accepted baseline" : "Generated", hasBaseline(safeResult) ? safeResult.summary.acceptedFindingCount : formatDate(safeResult.metadata.generatedAt))}
        </div>
      </div>
      <aside class="scorecard" aria-label="Risk score">
        <div>
          <p class="score-label">Risk score</p>
          <p class="score-value">${escapeHtml(safeResult.summary.riskScore)}</p>
        </div>
        <p class="score-caption">${escapeHtml(riskCaption(safeResult.summary.riskScore))}</p>
      </aside>
    </header>

    <section>
      <h2>Severity Summary</h2>
      <div class="severity-row">
        ${severityCard("critical", safeResult.summary.counts.critical)}
        ${severityCard("high", safeResult.summary.counts.high)}
        ${severityCard("medium", safeResult.summary.counts.medium)}
        ${severityCard("low", safeResult.summary.counts.low)}
      </div>
    </section>

    <section>
      <h2>Scanned Files</h2>
      ${renderScannedFiles(safeResult)}
    </section>

${hasPolicy(safeResult) ? `    <section>
      <h2>Policy</h2>
      ${renderPolicy(safeResult)}
    </section>` : ""}

    <section>
      <h2>MCP Server Inventory</h2>
      ${renderServerTable(servers, safeResult.metadata.cwd)}
    </section>

    <section>
      <h2>Active Findings</h2>
      ${renderFindingsTable(findings)}
    </section>

${hasBaseline(safeResult) ? `    <section>
      <h2>Accepted Baseline Findings</h2>
      ${renderAcceptedFindingsTable(acceptedFindings)}
    </section>` : ""}

    <section class="notes">
      <h2>Review Notes</h2>
      <ul>
        <li>Secret-like values are redacted before rendering this report.</li>
        <li>Review each server before granting access to files, shells, SaaS accounts, or production systems.</li>
        <li>This report assists security review and does not guarantee that every issue was found.</li>
      </ul>
    </section>
  </main>
</body>
</html>
`;
}

function cell(value) {
  return String(value).replaceAll("|", "\\|").replaceAll("\n", "<br>");
}

function sanitizeResult(result) {
  const cwd = result.metadata.cwd;
  return {
    metadata: {
      ...result.metadata,
      cwd: ".",
      home: "~",
      policyPath: result.metadata.policyPath ? displayPath(result.metadata.policyPath, cwd) : ""
    },
    policy: result.policy ? {
      ...result.policy,
      path: displayPath(result.policy.path, cwd)
    } : null,
    scannedFiles: result.scannedFiles.map((file) => displayPath(file, cwd)),
    servers: result.servers.map((server) => ({
      name: server.name,
      configPath: displayPath(server.configPath, cwd),
      command: server.command,
      args: server.args,
      env: redactEnv(server.env),
      envFile: server.envFile,
      cwd: server.cwd,
      url: server.url,
      headers: redactEnv(server.headers)
    })),
    findings: result.findings.map((finding) => ({
      ...finding,
      configPath: displayPath(finding.configPath, cwd)
    })),
    acceptedFindings: (result.acceptedFindings || []).map((finding) => ({
      ...finding,
      configPath: displayPath(finding.configPath, cwd)
    })),
    summary: result.summary,
    baseline: result.baseline || { enabled: false }
  };
}

function buildSarifRules(findings) {
  const unique = new Map();
  for (const finding of findings) {
    if (unique.has(finding.id)) continue;
    unique.set(finding.id, {
      id: finding.id,
      name: finding.id,
      shortDescription: {
        text: finding.title
      },
      fullDescription: {
        text: finding.title
      },
      help: {
        text: finding.recommendation,
        markdown: finding.recommendation
      },
      defaultConfiguration: {
        level: sarifLevel(finding.severity)
      },
      properties: {
        severity: finding.severity,
        tags: ["mcp", "ai-agent", "security"]
      }
    });
  }
  return [...unique.values()];
}

function sarifResult(finding, cwd) {
  return {
    ruleId: finding.id,
    level: sarifLevel(finding.severity),
    message: {
      text: `${finding.title}. ${finding.evidence} Fix: ${finding.recommendation}`
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: uriFromPath(finding.configPath, cwd)
          },
          region: {
            startLine: 1,
            startColumn: 1
          }
        },
        logicalLocations: [
          {
            name: finding.serverName,
            kind: "object"
          }
        ]
      }
    ],
    partialFingerprints: {
      "mcp-guard/rule-server-evidence": finding.fingerprint || stableHash(`${finding.id}:${finding.serverName}:${finding.evidence}`)
    },
    properties: {
      severity: finding.severity,
      serverName: finding.serverName,
      evidence: finding.evidence,
      recommendation: finding.recommendation
    }
  };
}

function sarifLevel(severity) {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

function uriFromPath(filePath, cwd) {
  const display = displayPath(filePath, cwd) || ".";
  return display.split("/").map(encodeURIComponent).join("/");
}

function metric(label, value) {
  return `<div class="metric"><strong>${escapeHtml(value)}</strong><span>${escapeHtml(label)}</span></div>`;
}

function severityCard(severity, count) {
  return `<div class="severity ${severity}"><b>${escapeHtml(count)}</b><span>${escapeHtml(severity)}</span></div>`;
}

function renderScannedFiles(result) {
  if (result.scannedFiles.length === 0) {
    return `<p class="empty">No MCP config files were found.</p>`;
  }

  const items = result.scannedFiles
    .map((file) => `<tr><td><code>${escapeHtml(displayPath(file, result.metadata.cwd))}</code></td></tr>`)
    .join("");

  return `<div class="table-wrap"><table><thead><tr><th>Path</th></tr></thead><tbody>${items}</tbody></table></div>`;
}

function renderPolicy(result) {
  const policy = result.policy;
  const rows = [
    ["Path", policy.path],
    ["Allowed commands", policy.allowedCommands.join(", ") || "-"],
    ["Allowed packages", policy.allowedPackages.join(", ") || "-"],
    ["Allowed directories", policy.allowedDirectories.join(", ") || "-"],
    ["Allowed remote URLs", policy.allowedRemoteUrls.join(", ") || "-"]
  ].map(([key, value]) => `<tr><th>${escapeHtml(key)}</th><td>${codeOrDash(value)}</td></tr>`).join("");

  return `<div class="table-wrap"><table><tbody>${rows}</tbody></table></div>`;
}

function renderServerTable(servers, cwd) {
  if (servers.length === 0) {
    return `<p class="empty">No MCP servers were found.</p>`;
  }

  const rows = servers.map((server) => {
    const env = kvList(server.env);
    const headers = kvList(server.headers);
    return `<tr>
      <td><strong>${escapeHtml(server.name)}</strong><br><code>${escapeHtml(displayPath(server.configPath, cwd))}</code></td>
      <td>${codeOrDash(server.command)}</td>
      <td>${codeOrDash(server.args.join(" "))}</td>
      <td>${codeOrDash(server.cwd)}</td>
      <td>${codeOrDash(server.url)}</td>
      <td>${codeOrDash(server.envFile)}</td>
      <td>${env || "-"}</td>
      <td>${headers || "-"}</td>
    </tr>`;
  }).join("");

  return `<div class="table-wrap"><table>
    <thead><tr><th>Server</th><th>Command</th><th>Args</th><th>CWD</th><th>URL</th><th>Env file</th><th>Env</th><th>Headers</th></tr></thead>
    <tbody>${rows}</tbody>
  </table></div>`;
}

function renderFindingsTable(findings) {
  if (findings.length === 0) {
    return `<p class="empty">No active findings. Keep reviewing new MCP servers and agent tools before adding them.</p>`;
  }

  const rows = findings.map((finding) => `<tr>
    <td><span class="pill ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span></td>
    <td><code>${escapeHtml(finding.id)}</code></td>
    <td>${escapeHtml(finding.serverName)}</td>
    <td>${escapeHtml(finding.title)}</td>
    <td>${codeOrDash(finding.evidence)}</td>
    <td><code>${escapeHtml(finding.fingerprint)}</code></td>
    <td>${escapeHtml(finding.recommendation)}</td>
  </tr>`).join("");

  return `<div class="table-wrap"><table>
    <thead><tr><th>Severity</th><th>Rule</th><th>Server</th><th>Finding</th><th>Evidence</th><th>Fingerprint</th><th>Recommendation</th></tr></thead>
    <tbody>${rows}</tbody>
  </table></div>`;
}

function renderAcceptedFindingsTable(findings) {
  if (findings.length === 0) {
    return `<p class="empty">No current findings matched the baseline.</p>`;
  }

  const rows = findings.map((finding) => `<tr>
    <td><span class="pill ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span></td>
    <td><code>${escapeHtml(finding.id)}</code></td>
    <td>${escapeHtml(finding.serverName)}</td>
    <td>${escapeHtml(finding.title)}</td>
    <td><code>${escapeHtml(finding.fingerprint)}</code></td>
    <td>${escapeHtml(finding.acceptedReason || "-")}</td>
  </tr>`).join("");

  return `<div class="table-wrap"><table>
    <thead><tr><th>Severity</th><th>Rule</th><th>Server</th><th>Finding</th><th>Fingerprint</th><th>Reason</th></tr></thead>
    <tbody>${rows}</tbody>
  </table></div>`;
}

function kvList(record) {
  return Object.entries(record || {})
    .map(([key, value]) => `<code>${escapeHtml(key)}=${escapeHtml(value)}</code>`)
    .join("<br>");
}

function codeOrDash(value) {
  if (!value) return "-";
  return `<code>${escapeHtml(value)}</code>`;
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

function riskToneForScore(score) {
  if (score >= 80) return "critical";
  if (score >= 50) return "high";
  if (score >= 20) return "medium";
  return "low";
}

function riskCaption(score) {
  if (score >= 80) return "Critical review recommended before enabling these tools.";
  if (score >= 50) return "High risk configuration; review before team use.";
  if (score >= 20) return "Moderate risk; confirm the intended permission scope.";
  return "Low risk based on the current rule set.";
}

function hasBaseline(result) {
  return Boolean(result.baseline?.enabled);
}

function hasPolicy(result) {
  return Boolean(result.policy);
}

function hasAcceptedFindings(result) {
  return (result.acceptedFindings || []).length > 0;
}

function inlineList(items) {
  if (!items || items.length === 0) return "not restricted";
  return items.map((item) => `\`${item}\``).join(", ");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
