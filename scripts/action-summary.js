#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";

const [jsonReportPath, markdownReportPath, htmlReportPath, sarifReportPath, failOn, executiveSummaryPath, remediationReportPath, maybeRemediationChecklistPath, maybeAuditManifestPath] = process.argv.slice(2);
let remediationChecklistPath = maybeRemediationChecklistPath;
let auditManifestPath = maybeAuditManifestPath;

if (!auditManifestPath && remediationChecklistPath && path.basename(remediationChecklistPath) === "mcp-guard-audit-manifest.json") {
  auditManifestPath = remediationChecklistPath;
  remediationChecklistPath = "";
}

if (!jsonReportPath) {
  process.stderr.write("Usage: action-summary.js <json-report> <markdown-report> <html-report> <sarif-report> <fail-on> [executive-summary] [remediation-report] [remediation-checklist] [audit-manifest]\n");
  process.exit(1);
}

const report = JSON.parse(fs.readFileSync(jsonReportPath, "utf8"));
const counts = report.summary.counts;
const topFindings = report.findings.slice(0, 8);
const acceptedCount = report.summary.acceptedFindingCount || 0;

const lines = [];
lines.push("## mcp-guard scan");
lines.push("");
lines.push(`Risk score: **${report.summary.riskScore}**`);
lines.push("");
lines.push("| Severity | Count |");
lines.push("| --- | ---: |");
lines.push(`| Critical | ${counts.critical} |`);
lines.push(`| High | ${counts.high} |`);
lines.push(`| Medium | ${counts.medium} |`);
lines.push(`| Low | ${counts.low} |`);
lines.push("");
lines.push(`Scanned files: **${report.summary.scannedFileCount}**`);
lines.push(`MCP servers: **${report.summary.serverCount}**`);
lines.push(`Active findings: **${report.summary.findingCount}**`);
if (acceptedCount > 0 || report.baseline?.enabled) {
  lines.push(`Accepted by baseline: **${acceptedCount}**`);
}
if (report.policy?.path) {
  lines.push(`Policy: **${report.policy.path}**`);
}
lines.push(`Fail threshold: **${failOn || "high"}**`);
lines.push("");

if (topFindings.length === 0) {
  lines.push("No active findings.");
} else {
  lines.push("### Top active findings");
  lines.push("");
  lines.push("| Severity | Rule | Server | Finding |");
  lines.push("| --- | --- | --- | --- |");
  for (const finding of topFindings) {
    lines.push(`| ${cell(finding.severity)} | ${cell(finding.id)} | ${cell(finding.serverName)} | ${cell(finding.title)} |`);
  }
}

if (topFindings.length > 0) {
  lines.push("");
  lines.push("### First remediation steps");
  lines.push("");
  for (const finding of topFindings.slice(0, 5)) {
    lines.push(`- [ ] **${cell(finding.severity)} ${cell(finding.id)}** \`${cell(finding.serverName)}\`: ${cell(finding.recommendation)}`);
  }
}

lines.push("");
lines.push("### Reports");
lines.push("");
lines.push(`- Markdown: \`${relative(markdownReportPath)}\``);
lines.push(`- HTML: \`${relative(htmlReportPath)}\``);
lines.push(`- JSON: \`${relative(jsonReportPath)}\``);
lines.push(`- SARIF: \`${relative(sarifReportPath)}\``);
if (executiveSummaryPath) {
  lines.push(`- Executive summary: \`${relative(executiveSummaryPath)}\``);
}
if (remediationReportPath) {
  lines.push(`- Remediation: \`${relative(remediationReportPath)}\``);
}
if (remediationChecklistPath) {
  lines.push(`- Remediation checklist: \`${relative(remediationChecklistPath)}\``);
}
if (auditManifestPath) {
  lines.push(`- Audit manifest: \`${relative(auditManifestPath)}\``);
}
lines.push("");

process.stdout.write(`${lines.join("\n")}\n`);

function cell(value) {
  return String(value ?? "").replaceAll("|", "\\|").replaceAll("\n", " ");
}

function relative(filePath) {
  if (!filePath) return "";
  return path.relative(process.cwd(), path.resolve(filePath)) || ".";
}
