#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";

const [jsonReportPath, markdownReportPath, htmlReportPath, sarifReportPath, failOn] = process.argv.slice(2);

if (!jsonReportPath) {
  process.stderr.write("Usage: action-comment.js <json-report> <markdown-report> <html-report> <sarif-report> <fail-on>\n");
  process.exit(1);
}

const report = JSON.parse(fs.readFileSync(jsonReportPath, "utf8"));
const counts = report.summary.counts;
const findings = report.findings || [];
const acceptedCount = report.summary.acceptedFindingCount || 0;
const runUrl = process.env.GITHUB_SERVER_URL && process.env.GITHUB_REPOSITORY && process.env.GITHUB_RUN_ID
  ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`
  : "";
const status = findings.length === 0 ? "passed" : "needs review";

const lines = [];
lines.push("<!-- mcp-guard-comment -->");
lines.push("## mcp-guard MCP security scan");
lines.push("");
lines.push(`Status: **${status}**`);
lines.push(`Risk score: **${report.summary.riskScore}**`);
lines.push(`Active findings: **${report.summary.findingCount}**`);
if (acceptedCount > 0 || report.baseline?.enabled) {
  lines.push(`Accepted by baseline: **${acceptedCount}**`);
}
lines.push(`Fail threshold: **${failOn || "high"}**`);
if (runUrl) {
  lines.push(`Workflow run: ${runUrl}`);
}
lines.push("");
lines.push("| Critical | High | Medium | Low |");
lines.push("| ---: | ---: | ---: | ---: |");
lines.push(`| ${counts.critical} | ${counts.high} | ${counts.medium} | ${counts.low} |`);
lines.push("");

if (findings.length === 0) {
  lines.push("No active findings met the current scan. Baseline-accepted findings do not block this PR.");
} else {
  lines.push("### Top active findings");
  lines.push("");
  lines.push("| Severity | Rule | Server | Finding |");
  lines.push("| --- | --- | --- | --- |");
  for (const finding of findings.slice(0, 6)) {
    lines.push(`| ${cell(finding.severity)} | ${cell(finding.id)} | ${cell(finding.serverName)} | ${cell(finding.title)} |`);
  }
}

lines.push("");
lines.push("### Artifacts");
lines.push("");
lines.push(`- Markdown: \`${relative(markdownReportPath)}\``);
lines.push(`- HTML: \`${relative(htmlReportPath)}\``);
lines.push(`- JSON: \`${relative(jsonReportPath)}\``);
lines.push(`- SARIF: \`${relative(sarifReportPath)}\``);
lines.push("");

process.stdout.write(`${lines.join("\n")}\n`);

function cell(value) {
  return String(value ?? "").replaceAll("|", "\\|").replaceAll("\n", " ");
}

function relative(filePath) {
  if (!filePath) return "";
  return path.relative(process.cwd(), path.resolve(filePath)) || ".";
}
