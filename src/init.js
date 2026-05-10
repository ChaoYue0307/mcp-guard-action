import fs from "node:fs/promises";
import path from "node:path";
import { writeBaselineFile } from "./baseline.js";
import { discoverConfigFiles } from "./discovery.js";
import { displayPath } from "./fingerprint.js";
import { scan } from "./scan.js";

export async function initProject({
  cwd,
  env,
  configPaths = [],
  includeDefaults = true,
  workflowPath,
  baselinePath,
  failOn = "high",
  commentPr = true,
  uploadSarif = false,
  writeBaseline = false,
  useBaseline = false,
  baselineReason = "Accepted current MCP findings",
  force = false,
  dryRun = false,
  toolVersion
}) {
  const discoveredConfigPaths = configPaths.length === 0 && includeDefaults
    ? await discoverConfigFiles({ cwd, env })
    : [];
  const workflowConfigPath = selectWorkflowConfigPath({
    cwd,
    explicitConfigPaths: configPaths,
    discoveredConfigPaths
  });
  const files = [];

  if (writeBaseline) {
    const baselineConfigPaths = configPaths.length > 0
      ? configPaths
      : workflowConfigPath
        ? [workflowConfigPath]
        : [];
    if (baselineConfigPaths.length === 0) {
      throw new Error("No project MCP config found for baseline generation. Add .mcp.json, pass --config, or run init without --write-baseline.");
    }
    const result = await scan({
      cwd,
      env,
      configPaths: baselineConfigPaths,
      includeDefaults: false,
      toolVersion
    });
    const baseline = await writeBaselineFileIfAllowed(baselinePath, result, {
      reason: baselineReason,
      force,
      dryRun
    });
    files.push({
      type: "baseline",
      path: baselinePath,
      action: baseline.action,
      findingCount: baseline.findingCount
    });
  }

  const workflow = renderGithubWorkflow({
    actionRef: `ChaoYue0307/mcp-guard-action@v${toolVersion}`,
    configPath: workflowConfigPath ? displayPath(workflowConfigPath, cwd) : "",
    baselinePath: useBaseline || writeBaseline ? displayPath(baselinePath, cwd) : "",
    failOn,
    commentPr,
    uploadSarif
  });
  const workflowWrite = await writeTextFileIfAllowed(workflowPath, workflow, { force, dryRun });
  files.push({
    type: "workflow",
    path: workflowPath,
    action: workflowWrite.action
  });

  return {
    dryRun,
    workflowPath,
    baselinePath,
    configPath: workflowConfigPath,
    discoveredConfigPaths,
    files,
    nextSteps: buildNextSteps({ workflowPath, baselinePath, writeBaseline, uploadSarif })
  };
}

export function renderInitSummary(result, cwd) {
  const lines = ["mcp-guard init completed"];

  if (result.dryRun) {
    lines[0] = "mcp-guard init dry run";
  }

  if (result.configPath) {
    lines.push(`Config: ${displayPath(result.configPath, cwd)}`);
  } else {
    lines.push("Config: default discovery paths");
  }

  for (const file of result.files) {
    const label = file.action === "skipped" ? "Skipped" : actionLabel(file.action);
    const suffix = file.type === "baseline" ? ` (${file.findingCount} findings)` : "";
    lines.push(`${label}: ${displayPath(file.path, cwd)}${suffix}`);
  }

  lines.push("");
  lines.push("Next:");
  for (const step of result.nextSteps) {
    lines.push(`- ${step}`);
  }

  return `${lines.join("\n")}\n`;
}

export function renderGithubWorkflow({ actionRef, configPath, baselinePath, failOn, commentPr, uploadSarif }) {
  const permissions = ["  contents: read"];
  if (commentPr) {
    permissions.push("  pull-requests: write");
  }
  if (uploadSarif) {
    permissions.push("  security-events: write");
  }

  const inputs = [];
  if (configPath) {
    inputs.push(`          config: ${quoteYaml(configPath)}`);
  }
  if (baselinePath) {
    inputs.push(`          baseline: ${quoteYaml(baselinePath)}`);
  }
  inputs.push(`          fail-on: ${quoteYaml(failOn)}`);
  if (commentPr) {
    inputs.push('          comment-pr: "true"');
  }
  if (uploadSarif) {
    inputs.push('          upload-sarif: "true"');
  }

  return `name: mcp-guard

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
${permissions.join("\n")}

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: ${actionRef}
        with:
${inputs.join("\n")}
`;
}

function selectWorkflowConfigPath({ cwd, explicitConfigPaths, discoveredConfigPaths }) {
  if (explicitConfigPaths.length > 0) {
    return explicitConfigPaths[0];
  }

  return discoveredConfigPaths.find((filePath) => isInsideDirectory(filePath, cwd)) || "";
}

async function writeBaselineFileIfAllowed(filePath, result, { reason, force, dryRun }) {
  const existing = await fileExists(filePath);
  if (existing && !force) {
    throw new Error(`Refusing to overwrite ${filePath}; use --force to replace it.`);
  }

  if (dryRun) {
    return {
      action: existing ? "would-overwrite" : "would-create",
      findingCount: result.findings.length + result.acceptedFindings.length
    };
  }

  const baseline = await writeBaselineFile(filePath, result, { reason });
  return {
    action: existing ? "overwritten" : "created",
    findingCount: baseline.findings.length
  };
}

async function writeTextFileIfAllowed(filePath, content, { force, dryRun }) {
  const existing = await fileExists(filePath);
  if (existing && !force) {
    throw new Error(`Refusing to overwrite ${filePath}; use --force to replace it.`);
  }

  if (dryRun) {
    return {
      action: existing ? "would-overwrite" : "would-create"
    };
  }

  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, content, "utf8");
  return {
    action: existing ? "overwritten" : "created"
  };
}

async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

function buildNextSteps({ workflowPath, baselinePath, writeBaseline, uploadSarif }) {
  const steps = [
    `Review ${path.basename(workflowPath)} before committing it.`,
    "Run mcp-guard scan locally and confirm the findings are expected.",
    "Commit the workflow and open a pull request that changes MCP config to verify the check."
  ];

  if (writeBaseline) {
    steps.splice(1, 0, `Review ${path.basename(baselinePath)} because accepted findings will not fail CI.`);
  }

  if (uploadSarif) {
    steps.push("Confirm GitHub code scanning is enabled for SARIF results.");
  }

  return steps;
}

function actionLabel(action) {
  if (action === "would-create") return "Would create";
  if (action === "would-overwrite") return "Would overwrite";
  if (action === "overwritten") return "Overwrote";
  return "Created";
}

function isInsideDirectory(filePath, directory) {
  const relative = path.relative(path.resolve(directory), path.resolve(filePath));
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function quoteYaml(value) {
  if (/^[A-Za-z0-9_./-]+$/.test(value)) {
    return value;
  }
  return JSON.stringify(value);
}
