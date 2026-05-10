import fs from "node:fs/promises";
import path from "node:path";
import { applyBaseline, loadBaselineFile, writeBaselineFile } from "./baseline.js";
import { initProject, renderInitSummary } from "./init.js";
import { scan } from "./scan.js";
import { generateHtmlReport, generateJsonReport, generateMarkdownReport, generateSarifReport, generateTextReport } from "./report.js";
import { compareSeverity, severityRank } from "./severity.js";

const VERSION = "0.4.2";

export async function runCli(argv, io) {
  const args = argv.slice(2);
  const command = args[0];

  if (!command || command === "help" || command === "--help" || command === "-h") {
    io.stdout.write(helpText());
    return 0;
  }

  if (command === "version" || command === "--version" || command === "-v") {
    io.stdout.write(`${VERSION}\n`);
    return 0;
  }

  if (command === "init") {
    if (args.includes("--help") || args.includes("-h")) {
      io.stdout.write(helpText());
      return 0;
    }

    const options = parseInitArgs(args.slice(1), io.cwd);
    const result = await initProject({
      cwd: options.cwd,
      env: io.env,
      configPaths: options.configPaths,
      includeDefaults: options.includeDefaults,
      workflowPath: options.workflowPath,
      baselinePath: options.baselinePath,
      failOn: options.failOn,
      commentPr: options.commentPr,
      uploadSarif: options.uploadSarif,
      writeBaseline: options.writeBaseline,
      useBaseline: options.useBaseline,
      baselineReason: options.baselineReason,
      force: options.force,
      dryRun: options.dryRun,
      toolVersion: VERSION
    });
    io.stdout.write(renderInitSummary(result, options.cwd));
    return 0;
  }

  if (command !== "scan") {
    io.stderr.write(`Unknown command: ${command}\n\n`);
    io.stderr.write(helpText());
    process.exitCode = 1;
    return 1;
  }

  if (args.includes("--help") || args.includes("-h")) {
    io.stdout.write(helpText());
    return 0;
  }

  const options = parseScanArgs(args.slice(1), io.cwd);
  const result = await scan({
    cwd: options.cwd,
    env: io.env,
    configPaths: options.configPaths,
    includeDefaults: options.includeDefaults,
    toolVersion: VERSION
  });

  if (options.writeBaselinePath) {
    const baseline = await writeBaselineFile(options.writeBaselinePath, result, {
      reason: options.baselineReason
    });
    io.stderr.write(`Wrote baseline with ${baseline.findings.length} findings to ${options.writeBaselinePath}\n`);
  }

  const baseline = options.baselinePath ? await loadBaselineFile(options.baselinePath) : null;
  const reportResult = baseline ? applyBaseline(result, baseline, { baselinePath: options.baselinePath }) : result;

  const report = renderReport(reportResult, options.format);
  if (options.outputPath) {
    await fs.mkdir(path.dirname(options.outputPath), { recursive: true });
    await fs.writeFile(options.outputPath, report, "utf8");
    io.stdout.write(`Wrote ${options.format} report to ${options.outputPath}\n`);
    io.stdout.write(generateTextReport(reportResult));
  } else {
    io.stdout.write(report);
  }

  if (options.failOn !== "none" && shouldFail(reportResult, options.failOn)) {
    process.exitCode = 2;
    return 2;
  }

  return 0;
}

function parseInitArgs(args, defaultCwd) {
  const options = {
    cwd: defaultCwd,
    configPaths: [],
    includeDefaults: true,
    workflowPath: "",
    baselinePath: "",
    failOn: "high",
    commentPr: true,
    uploadSarif: false,
    writeBaseline: false,
    useBaseline: false,
    baselineReason: "Accepted current MCP findings",
    force: false,
    dryRun: false
  };
  options.workflowPath = path.join(options.cwd, ".github", "workflows", "mcp-guard.yml");
  options.baselinePath = path.join(options.cwd, ".mcp-guard-baseline.json");
  let workflowPathProvided = false;
  let baselinePathProvided = false;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--config" || arg === "-c") {
      options.configPaths.push(resolveInputPath(readValue(args, index, arg), options.cwd));
      index += 1;
    } else if (arg === "--workflow") {
      options.workflowPath = resolveInputPath(readValue(args, index, arg), options.cwd);
      workflowPathProvided = true;
      index += 1;
    } else if (arg === "--baseline" || arg === "--allowlist") {
      options.baselinePath = resolveInputPath(readValue(args, index, arg), options.cwd);
      options.useBaseline = true;
      baselinePathProvided = true;
      index += 1;
    } else if (arg === "--write-baseline" || arg === "--write-allowlist") {
      options.writeBaseline = true;
      options.useBaseline = true;
    } else if (arg === "--baseline-reason") {
      options.baselineReason = readValue(args, index, arg);
      index += 1;
    } else if (arg === "--fail-on") {
      options.failOn = readValue(args, index, arg);
      index += 1;
      if (!["critical", "high", "medium", "low", "none"].includes(options.failOn)) {
        throw new Error("--fail-on must be one of: critical, high, medium, low, none");
      }
    } else if (arg === "--comment-pr") {
      options.commentPr = true;
    } else if (arg === "--no-comment-pr") {
      options.commentPr = false;
    } else if (arg === "--upload-sarif") {
      options.uploadSarif = true;
    } else if (arg === "--cwd") {
      options.cwd = path.resolve(readValue(args, index, arg));
      if (!workflowPathProvided) {
        options.workflowPath = path.join(options.cwd, ".github", "workflows", "mcp-guard.yml");
      }
      if (!baselinePathProvided) {
        options.baselinePath = path.join(options.cwd, ".mcp-guard-baseline.json");
      }
      index += 1;
    } else if (arg === "--no-defaults") {
      options.includeDefaults = false;
    } else if (arg === "--force") {
      options.force = true;
    } else if (arg === "--dry-run") {
      options.dryRun = true;
    } else {
      throw new Error(`Unknown init option: ${arg}`);
    }
  }

  return options;
}

function parseScanArgs(args, defaultCwd) {
  const options = {
    cwd: defaultCwd,
    configPaths: [],
    includeDefaults: true,
    outputPath: "",
    format: "text",
    failOn: "none",
    baselinePath: "",
    writeBaselinePath: "",
    baselineReason: "Accepted current MCP findings"
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--config" || arg === "-c") {
      options.configPaths.push(resolveInputPath(readValue(args, index, arg), options.cwd));
      index += 1;
    } else if (arg === "--output" || arg === "-o") {
      options.outputPath = resolveInputPath(readValue(args, index, arg), options.cwd);
      index += 1;
    } else if (arg === "--format" || arg === "-f") {
      options.format = readValue(args, index, arg);
      index += 1;
      if (!["text", "markdown", "json", "html", "sarif"].includes(options.format)) {
        throw new Error("--format must be one of: text, markdown, json, html, sarif");
      }
    } else if (arg === "--fail-on") {
      options.failOn = readValue(args, index, arg);
      index += 1;
      if (!["critical", "high", "medium", "low", "none"].includes(options.failOn)) {
        throw new Error("--fail-on must be one of: critical, high, medium, low, none");
      }
    } else if (arg === "--baseline" || arg === "--allowlist") {
      options.baselinePath = resolveInputPath(readValue(args, index, arg), options.cwd);
      index += 1;
    } else if (arg === "--write-baseline" || arg === "--write-allowlist") {
      options.writeBaselinePath = resolveInputPath(readValue(args, index, arg), options.cwd);
      index += 1;
    } else if (arg === "--baseline-reason") {
      options.baselineReason = readValue(args, index, arg);
      index += 1;
    } else if (arg === "--cwd") {
      options.cwd = path.resolve(readValue(args, index, arg));
      index += 1;
    } else if (arg === "--no-defaults") {
      options.includeDefaults = false;
    } else {
      throw new Error(`Unknown scan option: ${arg}`);
    }
  }

  return options;
}

function readValue(args, index, optionName) {
  const value = args[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`${optionName} requires a value`);
  }
  return value;
}

function resolveInputPath(value, cwd) {
  return path.isAbsolute(value) ? value : path.resolve(cwd, value);
}

function renderReport(result, format) {
  if (format === "json") {
    return `${generateJsonReport(result)}\n`;
  }
  if (format === "markdown") {
    return generateMarkdownReport(result);
  }
  if (format === "html") {
    return generateHtmlReport(result);
  }
  if (format === "sarif") {
    return `${generateSarifReport(result)}\n`;
  }
  return generateTextReport(result);
}

function shouldFail(result, failOn) {
  const threshold = severityRank(failOn);
  return result.findings.some((finding) => compareSeverity(finding.severity, threshold) >= 0);
}

function helpText() {
  return `mcp-guard ${VERSION}

Open-source scanner for risky MCP server and AI agent tool configuration.

Usage:
  mcp-guard scan [options]
  mcp-guard init [options]
  mcp-guard version
  mcp-guard help

Init options:
      --workflow <path>     Workflow path to create. Default: .github/workflows/mcp-guard.yml.
  -c, --config <path>       MCP config path to reference in the workflow. Can be repeated for baseline generation.
      --fail-on <severity>  Workflow fail threshold. Default: high.
      --baseline <path>     Reference an existing baseline JSON file in the workflow.
      --write-baseline      Generate a baseline from current findings and reference it in the workflow.
      --baseline-reason <text>
                            Reason stored for newly written baseline entries.
      --comment-pr          Enable pull request comments. Default.
      --no-comment-pr       Do not add pull request comment permission or input.
      --upload-sarif        Upload SARIF to GitHub code scanning.
      --cwd <path>          Project directory to initialize.
      --no-defaults         Only scan paths passed with --config for baseline generation.
      --force               Overwrite existing workflow or baseline files.
      --dry-run             Print planned files without writing them.

Scan options:
  -c, --config <path>       Scan a specific MCP config file. Can be repeated.
  -o, --output <path>       Write report to a file.
  -f, --format <format>     text, markdown, json, html, or sarif. Default: text.
      --fail-on <severity>  Exit 2 when finding severity is at least threshold.
                            critical, high, medium, low, none. Default: none.
      --baseline <path>     Accept matching known findings from a baseline JSON file.
      --write-baseline <path>
                            Write current findings to a baseline JSON file.
      --baseline-reason <text>
                            Reason stored for newly written baseline entries.
      --cwd <path>          Working directory for project config discovery.
      --no-defaults         Only scan paths passed with --config.

Examples:
  mcp-guard init
  mcp-guard init --write-baseline --upload-sarif
  mcp-guard scan
  mcp-guard scan --format markdown --output mcp-guard-report.md
  mcp-guard scan --format html --output mcp-guard-report.html
  mcp-guard scan --format sarif --output mcp-guard.sarif
  mcp-guard scan --config .mcp.json --fail-on high
  mcp-guard scan --config .mcp.json --write-baseline .mcp-guard-baseline.json
  mcp-guard scan --config .mcp.json --baseline .mcp-guard-baseline.json --fail-on high
`;
}
