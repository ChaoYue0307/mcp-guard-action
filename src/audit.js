import fs from "node:fs/promises";
import crypto from "node:crypto";
import path from "node:path";
import { applyBaseline, loadBaselineFile } from "./baseline.js";
import { displayPath } from "./fingerprint.js";
import { generateHtmlReport, generateJsonReport, generateMarkdownReport, generateSarifReport } from "./report.js";
import { scan } from "./scan.js";

export const AUDIT_FILENAMES = {
  executiveSummary: "mcp-guard-executive-summary.md",
  remediation: "mcp-guard-remediation.md",
  remediationChecklist: "mcp-guard-remediation-checklist.md",
  markdownReport: "mcp-guard-report.md",
  htmlReport: "mcp-guard-report.html",
  jsonReport: "mcp-guard-report.json",
  sarifReport: "mcp-guard.sarif",
  manifest: "mcp-guard-audit-manifest.json"
};

export async function writeAuditPack({
  cwd,
  env,
  outputDir,
  configPaths = [],
  includeDefaults = true,
  baselinePath = "",
  policyPath = "",
  includePolicy = true,
  failOn = "none",
  toolVersion = "0.0.0"
}) {
  const rawResult = await scan({
    cwd,
    env,
    configPaths,
    includeDefaults,
    policyPath,
    includePolicy,
    toolVersion
  });
  const baseline = baselinePath ? await loadBaselineFile(baselinePath) : null;
  const result = baseline ? applyBaseline(rawResult, baseline, { baselinePath }) : rawResult;
  const resolvedOutputDir = path.resolve(cwd, outputDir || "mcp-guard-audit");
  const files = auditFilePaths(resolvedOutputDir);

  await fs.mkdir(resolvedOutputDir, { recursive: true });

  await Promise.all([
    fs.writeFile(files.executiveSummary, generateExecutiveSummary(result, { failOn }), "utf8"),
    fs.writeFile(files.remediation, generateRemediationPlan(result), "utf8"),
    fs.writeFile(files.remediationChecklist, generateRemediationChecklist(result), "utf8"),
    fs.writeFile(files.markdownReport, generateMarkdownReport(result), "utf8"),
    fs.writeFile(files.htmlReport, generateHtmlReport(result), "utf8"),
    fs.writeFile(files.jsonReport, `${generateJsonReport(result)}\n`, "utf8"),
    fs.writeFile(files.sarifReport, `${generateSarifReport(result)}\n`, "utf8")
  ]);

  const artifacts = await auditArtifacts(files, cwd);
  const manifest = buildAuditManifest(result, files, {
    cwd,
    outputDir: resolvedOutputDir,
    failOn,
    artifacts
  });
  await fs.writeFile(files.manifest, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

  return {
    result,
    files,
    manifest,
    outputDir: resolvedOutputDir
  };
}

export function auditFilePaths(outputDir) {
  return Object.fromEntries(
    Object.entries(AUDIT_FILENAMES).map(([key, filename]) => [key, path.join(outputDir, filename)])
  );
}

export function generateAuditSummary(result, { outputDir, files }) {
  const lines = [];
  lines.push("mcp-guard audit pack");
  lines.push(`Output directory: ${displayPath(outputDir, result.metadata.cwd)}`);
  lines.push(`Risk score: ${result.summary.riskScore}`);
  lines.push(`Active findings: ${result.summary.findingCount}`);
  lines.push(`Critical: ${result.summary.counts.critical}  High: ${result.summary.counts.high}  Medium: ${result.summary.counts.medium}  Low: ${result.summary.counts.low}`);
  if (result.policy?.path) {
    lines.push(`Policy: ${displayPath(result.policy.path, result.metadata.cwd)}`);
  }
  if (result.baseline?.enabled) {
    lines.push(`Accepted by baseline: ${result.summary.acceptedFindingCount || 0}`);
  }
  lines.push("");
  lines.push("Files:");
  for (const [label, filePath] of auditFileLabels(files)) {
    lines.push(`- ${label}: ${displayPath(filePath, result.metadata.cwd)}`);
  }
  return `${lines.join("\n")}\n`;
}

function generateExecutiveSummary(result, { failOn }) {
  const lines = [];
  const status = result.findings.length === 0 ? "Passed" : "Needs review";
  lines.push("# mcp-guard Executive Summary");
  lines.push("");
  lines.push(`Generated: ${result.metadata.generatedAt}`);
  lines.push(`Status: **${status}**`);
  lines.push(`Risk score: **${result.summary.riskScore}**`);
  lines.push(`Fail threshold: **${failOn}**`);
  lines.push("");
  lines.push("## Scope");
  lines.push("");
  lines.push(`- Scanned files: ${result.summary.scannedFileCount}`);
  lines.push(`- MCP servers: ${result.summary.serverCount}`);
  lines.push(`- Active findings: ${result.summary.findingCount}`);
  if (result.baseline?.enabled) {
    lines.push(`- Accepted by baseline: ${result.summary.acceptedFindingCount || 0}`);
  }
  if (result.policy?.path) {
    lines.push(`- Policy: \`${displayPath(result.policy.path, result.metadata.cwd)}\``);
  }
  lines.push(`- Critical: ${result.summary.counts.critical}`);
  lines.push(`- High: ${result.summary.counts.high}`);
  lines.push(`- Medium: ${result.summary.counts.medium}`);
  lines.push(`- Low: ${result.summary.counts.low}`);
  lines.push("");
  lines.push("## Decision Guidance");
  lines.push("");
  for (const item of decisionGuidance(result)) {
    lines.push(`- ${item}`);
  }
  lines.push("");
  lines.push("## Top Active Findings");
  lines.push("");
  if (result.findings.length === 0) {
    lines.push("No active findings were detected.");
  } else {
    lines.push("| Severity | Rule | Server | Finding |");
    lines.push("| --- | --- | --- | --- |");
    for (const finding of result.findings.slice(0, 8)) {
      lines.push(`| ${cell(finding.severity)} | ${cell(finding.id)} | ${cell(finding.serverName)} | ${cell(finding.title)} |`);
    }
  }
  lines.push("");
  lines.push("## Review Notes");
  lines.push("");
  lines.push("- Secret-like values are redacted before reports are written.");
  lines.push("- Review MCP servers before granting access to local files, shell commands, SaaS accounts, or production systems.");
  lines.push("- This audit pack is generated locally and does not upload MCP configuration to a hosted service.");
  lines.push("");
  return `${lines.join("\n")}\n`;
}

function generateRemediationPlan(result) {
  const lines = [];
  const byServer = groupFindingsByServer(result.findings);
  lines.push("# mcp-guard Remediation Plan");
  lines.push("");
  lines.push(`Generated: ${result.metadata.generatedAt}`);
  lines.push("");
  lines.push("## Priority");
  lines.push("");
  for (const item of remediationPriorities(result.findings)) {
    lines.push(`- ${item}`);
  }
  lines.push("");
  lines.push("## Findings By Server");
  lines.push("");
  if (byServer.size === 0) {
    lines.push("No active findings require remediation.");
  } else {
    for (const [serverName, findings] of byServer) {
      lines.push(`### ${serverName}`);
      lines.push("");
      lines.push("| Severity | Rule | Evidence | Recommended fix |");
      lines.push("| --- | --- | --- | --- |");
      for (const finding of findings) {
        lines.push(`| ${cell(finding.severity)} | ${cell(finding.id)} | ${cell(finding.evidence)} | ${cell(finding.recommendation)} |`);
      }
      lines.push("");
    }
  }
  if (result.acceptedFindings?.length > 0) {
    lines.push("## Baseline-Accepted Findings");
    lines.push("");
    lines.push("These findings are still present, but matched the provided baseline and did not block this run.");
    lines.push("");
    lines.push("| Severity | Rule | Server | Reason |");
    lines.push("| --- | --- | --- | --- |");
    for (const finding of result.acceptedFindings) {
      lines.push(`| ${cell(finding.severity)} | ${cell(finding.id)} | ${cell(finding.serverName)} | ${cell(finding.acceptedReason || "-")} |`);
    }
    lines.push("");
  }
  lines.push("## Handoff Checklist");
  lines.push("");
  lines.push("- Remove or replace critical shell and dangerous command findings before merging.");
  lines.push("- Pin remote MCP packages to exact versions and review package provenance.");
  lines.push("- Reduce filesystem scope to project-specific directories.");
  lines.push("- Move long-lived credentials out of MCP config files and rotate any exposed tokens.");
  lines.push("- Commit a reviewed `.mcp-guard-policy.json` for approved commands, packages, directories, and remote URLs.");
  lines.push("");
  return `${lines.join("\n")}\n`;
}

function generateRemediationChecklist(result) {
  const lines = [];
  lines.push("# mcp-guard Remediation Checklist");
  lines.push("");
  lines.push(`Generated: ${result.metadata.generatedAt}`);
  lines.push(`Risk score: **${result.summary.riskScore}**`);
  lines.push(`Active findings: **${result.summary.findingCount}**`);
  lines.push("");
  lines.push("## Release Gate");
  lines.push("");
  lines.push("- [ ] Critical findings are removed or the MCP server is redesigned.");
  lines.push("- [ ] High findings are reviewed before merge or rollout.");
  lines.push("- [ ] Any accepted residual risk is documented in policy or baseline.");
  lines.push("");
  lines.push("## Remediation Tasks");
  lines.push("");
  if (result.findings.length === 0) {
    lines.push("No active remediation tasks.");
  } else {
    lines.push("| Done | Priority | Rule | Server | Action | Fingerprint |");
    lines.push("| --- | --- | --- | --- | --- | --- |");
    for (const finding of result.findings) {
      lines.push(`| [ ] | ${cell(finding.severity)} | ${cell(finding.id)} | ${cell(finding.serverName)} | ${cell(remediationAction(finding))} | ${cell(finding.fingerprint)} |`);
    }
  }
  lines.push("");
  if (result.acceptedFindings?.length > 0) {
    lines.push("## Accepted Risk Review");
    lines.push("");
    lines.push("| Reviewed | Rule | Server | Reason | Fingerprint |");
    lines.push("| --- | --- | --- | --- | --- |");
    for (const finding of result.acceptedFindings) {
      lines.push(`| [ ] | ${cell(finding.id)} | ${cell(finding.serverName)} | ${cell(finding.acceptedReason || "-")} | ${cell(finding.fingerprint)} |`);
    }
    lines.push("");
  }
  lines.push("## Closeout");
  lines.push("");
  lines.push("- [ ] Re-run `mcp-guard audit` after changes.");
  lines.push("- [ ] Commit updated `.mcp-guard-policy.json` only for reviewed approvals.");
  lines.push("- [ ] Commit or update `.mcp-guard-baseline.json` only for intentionally accepted findings.");
  lines.push("");
  return `${lines.join("\n")}\n`;
}

function buildAuditManifest(result, files, { cwd, outputDir, failOn, artifacts }) {
  return {
    version: 1,
    tool: {
      name: "mcp-guard",
      version: result.metadata.toolVersion
    },
    generatedAt: result.metadata.generatedAt,
    status: result.findings.length === 0 ? "passed" : "needs_review",
    failOn,
    outputDir: displayPath(outputDir, cwd),
    summary: result.summary,
    policy: result.policy ? {
      path: displayPath(result.policy.path, cwd),
      allowedCommands: result.policy.allowedCommands,
      allowedPackages: result.policy.allowedPackages,
      allowedDirectories: result.policy.allowedDirectories,
      allowedRemoteUrls: result.policy.allowedRemoteUrls
    } : null,
    baseline: result.baseline || { enabled: false },
    files: Object.fromEntries(
      Object.entries(files).map(([key, filePath]) => [key, displayPath(filePath, cwd)])
    ),
    integrity: {
      algorithm: "sha256",
      artifacts
    }
  };
}

async function auditArtifacts(files, cwd) {
  const artifacts = [];
  for (const [key, filePath] of Object.entries(files)) {
    if (key === "manifest") continue;
    const content = await fs.readFile(filePath);
    artifacts.push({
      key,
      path: displayPath(filePath, cwd),
      bytes: content.byteLength,
      sha256: crypto.createHash("sha256").update(content).digest("hex")
    });
  }
  return artifacts;
}

function decisionGuidance(result) {
  if (result.findings.length === 0) {
    return ["No active findings were detected. Continue reviewing new MCP servers before adding them."];
  }

  const items = [];
  if (result.summary.counts.critical > 0) {
    items.push("Block merge or rollout until critical findings are removed or explicitly redesigned.");
  }
  if (result.summary.counts.high > 0) {
    items.push("Review high findings before merge, especially shell access, secrets, remote package execution, and broad filesystem scope.");
  }
  if (result.policy?.path) {
    items.push("Keep policy violations active until the command, package, directory, or remote endpoint has been approved.");
  } else {
    items.push("Add `.mcp-guard-policy.json` to turn this review into an enforceable team allowlist.");
  }
  if (!result.baseline?.enabled && result.findings.length > 0) {
    items.push("After remediation, generate a baseline only for intentionally accepted residual findings.");
  }
  return items;
}

function remediationPriorities(findings) {
  if (findings.length === 0) {
    return ["No active remediation items. Re-run the audit when MCP servers or agent tools change."];
  }

  const ids = new Set(findings.map((finding) => finding.id));
  const items = [];
  if (ids.has("MCP010") || ids.has("MCP050")) {
    items.push("Remove shell wrappers, inline scripts, and dangerous startup commands first.");
  }
  if (ids.has("MCP030") || ids.has("MCP061")) {
    items.push("Rotate exposed credentials and replace long-lived secrets with scoped, short-lived credentials.");
  }
  if (ids.has("MCP020") || ids.has("MCP021") || ids.has("MCP071")) {
    items.push("Pin and review remote MCP packages before allowing them in CI.");
  }
  if (ids.has("MCP040") || ids.has("MCP041") || ids.has("MCP072") || ids.has("MCP073")) {
    items.push("Constrain working directories and filesystem arguments to dedicated project workspaces.");
  }
  if (ids.has("MCP060") || ids.has("MCP074")) {
    items.push("Review remote MCP endpoints and keep an explicit allowlist for approved providers.");
  }
  return items.length > 0 ? items : ["Review each active finding and document the accepted remediation path."];
}

function remediationAction(finding) {
  const server = finding.serverName === "<workspace>" || finding.serverName === "<config>"
    ? "this config"
    : `server \`${finding.serverName}\``;

  if (finding.id === "MCP010") {
    return `Replace the shell wrapper for ${server} with a direct reviewed executable or checked-in script.`;
  }
  if (finding.id === "MCP011") {
    return `Move inline eval code for ${server} into reviewed source control.`;
  }
  if (finding.id === "MCP020" || finding.id === "MCP021" || finding.id === "MCP071") {
    return `Pin and approve the remote package used by ${server}.`;
  }
  if (finding.id === "MCP030" || finding.id === "MCP061") {
    return `Move credentials for ${server} out of MCP config and rotate any exposed tokens.`;
  }
  if (finding.id === "MCP040" || finding.id === "MCP041" || finding.id === "MCP072" || finding.id === "MCP073") {
    return `Constrain filesystem access for ${server} to a reviewed project directory.`;
  }
  if (finding.id === "MCP050") {
    return `Remove the dangerous startup operation from ${server} and run setup manually after review.`;
  }
  if (finding.id === "MCP060" || finding.id === "MCP074") {
    return `Review and allowlist the remote MCP endpoint used by ${server}.`;
  }
  if (finding.id === "MCP070") {
    return `Use an approved command for ${server} or update policy after review.`;
  }
  return finding.recommendation;
}

function groupFindingsByServer(findings) {
  const groups = new Map();
  for (const finding of findings) {
    const current = groups.get(finding.serverName) || [];
    current.push(finding);
    groups.set(finding.serverName, current);
  }
  return groups;
}

function auditFileLabels(files) {
  return [
    ["Executive summary", files.executiveSummary],
    ["Remediation plan", files.remediation],
    ["Remediation checklist", files.remediationChecklist],
    ["Markdown report", files.markdownReport],
    ["HTML report", files.htmlReport],
    ["JSON report", files.jsonReport],
    ["SARIF report", files.sarifReport],
    ["Manifest", files.manifest]
  ];
}

function cell(value) {
  return String(value ?? "").replaceAll("|", "\\|").replaceAll("\n", "<br>");
}
