import fs from "node:fs/promises";
import path from "node:path";
import { displayPath } from "./fingerprint.js";
import { commandBase, remotePackageSpec } from "./package-runner.js";
import { DEFAULT_POLICY_FILE } from "./policy.js";

const SHELL_COMMANDS = new Set(["sh", "bash", "zsh", "fish", "pwsh", "powershell", "cmd", "cmd.exe"]);
const CONTAINER_COMMANDS = new Set(["docker", "podman"]);
const CONTAINER_RISK_RULES = new Map([
  ["MCP080", "privileged container runtime"],
  ["MCP081", "Docker socket mount"],
  ["MCP082", "host networking"],
  ["MCP083", "broad host volume mount"]
]);
const BROAD_DIR_NAMES = new Set(["Desktop", "Documents", "Downloads"]);
const DOCKER_SOCKET_PATHS = new Set(["/var/run/docker.sock", "/run/docker.sock"]);

export function defaultPolicyOutputPath(cwd) {
  return path.join(cwd, DEFAULT_POLICY_FILE);
}

export function suggestPolicy(result, { cwd, home, includeRisky = false }) {
  const allowedCommands = new Set();
  const allowedPackages = new Set();
  const allowedDirectories = new Set();
  const allowedRemoteUrls = new Set();
  const skipped = [];
  const skippedKeys = new Set();
  const addSkipped = (field, value, reason, server) => {
    const key = `${field}\u0000${value}\u0000${reason}\u0000${server.name}`;
    if (skippedKeys.has(key)) return;
    skippedKeys.add(key);
    skipped.push(skippedItem(field, value, reason, server));
  };

  for (const server of result.servers) {
    const command = commandBase(server.command);
    if (command) {
      const riskyContainerReason = !includeRisky && CONTAINER_COMMANDS.has(command)
        ? containerRiskReason(result, server)
        : "";
      if (!includeRisky && SHELL_COMMANDS.has(command)) {
        addSkipped("allowedCommands", command, "shell wrapper command", server);
      } else if (riskyContainerReason) {
        addSkipped("allowedCommands", command, riskyContainerReason, server);
      } else {
        allowedCommands.add(command);
      }
    }

    const packageName = remotePackageIdentity(server);
    if (packageName) {
      allowedPackages.add(packageName);
    }

    for (const directory of candidateDirectories(server)) {
      const normalized = normalizePath(directory, { cwd, home });
      const broadReason = broadDirectoryReason(normalized, { cwd, home, original: directory });
      if (!includeRisky && broadReason) {
        addSkipped("allowedDirectories", directory, broadReason, server);
      } else {
        allowedDirectories.add(policyPathValue(normalized, { cwd, home }));
      }
    }

    if (server.url) {
      try {
        allowedRemoteUrls.add(normalizePolicyUrl(server.url));
      } catch {
        addSkipped("allowedRemoteUrls", server.url, "invalid URL", server);
      }
    }
  }

  return {
    policy: {
      version: 1,
      allowedCommands: sorted(allowedCommands),
      allowedPackages: sorted(allowedPackages),
      allowedDirectories: sorted(allowedDirectories),
      allowedRemoteUrls: sorted(allowedRemoteUrls)
    },
    skipped
  };
}

export async function writeSuggestedPolicyFile(filePath, suggestion, { force = false, dryRun = false }) {
  const existing = await fileExists(filePath);
  if (existing && !force && !dryRun) {
    throw new Error(`Refusing to overwrite ${filePath}; use --force to replace it.`);
  }

  if (dryRun) {
    return {
      action: existing ? "would-overwrite" : "would-create"
    };
  }

  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, `${JSON.stringify(suggestion.policy, null, 2)}\n`, "utf8");
  return {
    action: existing ? "overwritten" : "created"
  };
}

export function renderPolicySuggestionSummary({ scanResult, suggestion, writeResult, outputPath, cwd, dryRun }) {
  const lines = [dryRun ? "mcp-guard policy suggestion dry run" : "mcp-guard policy suggestion"];
  lines.push(`Scanned files: ${scanResult.scannedFiles.length}`);
  lines.push(`MCP servers: ${scanResult.servers.length}`);
  lines.push(`${actionLabel(writeResult.action)}: ${displayPath(outputPath, cwd)}`);
  lines.push("");
  lines.push("Suggested approvals:");
  lines.push(`- Commands: ${suggestion.policy.allowedCommands.length}`);
  lines.push(`- Remote packages: ${suggestion.policy.allowedPackages.length}`);
  lines.push(`- Directories: ${suggestion.policy.allowedDirectories.length}`);
  lines.push(`- Remote URLs: ${suggestion.policy.allowedRemoteUrls.length}`);
  lines.push(`- Skipped risky values: ${suggestion.skipped.length}`);

  if (suggestion.skipped.length > 0) {
    lines.push("");
    lines.push("Skipped for review:");
    for (const item of suggestion.skipped.slice(0, 10)) {
      lines.push(`- ${item.field} ${JSON.stringify(item.value)} on ${item.serverName}: ${item.reason}`);
    }
    if (suggestion.skipped.length > 10) {
      lines.push(`- ... ${suggestion.skipped.length - 10} more`);
    }
  }

  lines.push("");
  lines.push("Next:");
  lines.push(`- Review ${displayPath(outputPath, cwd)} before committing it.`);
  lines.push(`- Run mcp-guard scan --policy ${displayPath(outputPath, cwd)} to see policy findings.`);
  lines.push("- Do not add skipped values unless the team has explicitly approved that access.");

  return `${lines.join("\n")}\n`;
}

export function renderPolicySuggestionPreview(suggestion) {
  return `${JSON.stringify(suggestion.policy, null, 2)}\n`;
}

function remotePackageIdentity(server) {
  const packageSpec = remotePackageSpec(server);
  return packageSpec?.packageName || "";
}

function candidateDirectories(server) {
  const directories = [];
  if (server.cwd) {
    directories.push(server.cwd);
  }

  if (CONTAINER_COMMANDS.has(commandBase(server.command))) {
    directories.push(...containerMountSources(server.args));
    return directories;
  }

  for (const arg of server.args) {
    const value = filesystemPathFromArg(arg);
    if (value) {
      directories.push(value);
    }
  }

  return directories;
}

function filesystemPathFromArg(arg) {
  const value = valueFromArg(arg);
  if (!value) return "";
  if (value === "~" || value.startsWith("~/")) return value;
  if (value.startsWith("/") || value.startsWith("./") || value.startsWith("../")) return value;
  return "";
}

function valueFromArg(arg) {
  if (!arg) return "";
  const equalIndex = arg.indexOf("=");
  if (equalIndex > -1) return arg.slice(equalIndex + 1);
  if (arg.startsWith("/") || arg.startsWith("~") || arg.startsWith("./") || arg.startsWith("../")) return arg;
  return "";
}

function normalizePath(value, context) {
  if (!value) return "";
  if (value === "~") return path.normalize(context.home);
  if (value.startsWith("~/")) return path.join(context.home, value.slice(2));
  if (path.isAbsolute(value)) return path.normalize(value);
  return path.resolve(context.cwd, value);
}

function broadDirectoryReason(normalized, { cwd, home, original }) {
  const root = path.parse(normalized).root;
  if (DOCKER_SOCKET_PATHS.has(normalized) || DOCKER_SOCKET_PATHS.has(original)) return "Docker socket access";
  if (normalized === root || original === "/") return "root directory access";
  if (normalized === path.normalize(home) || original === "~") return "home directory access";

  const base = path.basename(normalized);
  if (BROAD_DIR_NAMES.has(base)) {
    return `${base} directory access`;
  }

  if (normalized === path.resolve(cwd)) {
    return "";
  }

  return "";
}

function policyPathValue(normalized, { cwd, home }) {
  const resolvedCwd = path.resolve(cwd);
  const resolvedHome = path.resolve(home);

  if (normalized === resolvedCwd) return ".";
  if (isInside(normalized, resolvedCwd)) {
    return `./${toPosix(path.relative(resolvedCwd, normalized))}`;
  }

  if (normalized === resolvedHome) return "~";
  if (isInside(normalized, resolvedHome)) {
    return `~/${toPosix(path.relative(resolvedHome, normalized))}`;
  }

  return normalized;
}

function normalizePolicyUrl(value) {
  const parsed = new URL(value);
  const pathname = parsed.pathname === "/" ? "" : parsed.pathname.replace(/\/+$/, "");
  return `${parsed.origin}${pathname}`;
}

function skippedItem(field, value, reason, server) {
  return {
    field,
    value,
    reason,
    serverName: server.name
  };
}

function sorted(items) {
  return [...items].sort((a, b) => a.localeCompare(b));
}

function isInside(filePath, directory) {
  const relative = path.relative(directory, filePath);
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}

function toPosix(value) {
  return value.split(path.sep).join("/");
}

function actionLabel(action) {
  if (action === "would-create") return "Would create";
  if (action === "would-overwrite") return "Would overwrite";
  if (action === "overwritten") return "Overwrote";
  return "Created";
}

function containerRiskReason(result, server) {
  const finding = (result.findings || []).find((item) =>
    item.serverName === server.name && CONTAINER_RISK_RULES.has(item.id)
  );
  return finding ? CONTAINER_RISK_RULES.get(finding.id) : "";
}

function containerMountSources(args) {
  const sources = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg) continue;

    if (arg === "-v" || arg === "--volume") {
      const source = volumeSource(args[index + 1] || "");
      if (source) sources.push(source);
      index += 1;
      continue;
    }

    if (arg === "--mount") {
      const source = bindMountSource(args[index + 1] || "");
      if (source) sources.push(source);
      index += 1;
      continue;
    }

    const volume = optionValue(arg, ["-v", "--volume"]);
    if (volume) {
      const source = volumeSource(volume);
      if (source) sources.push(source);
      continue;
    }

    const mount = optionValue(arg, ["--mount"]);
    if (mount) {
      const source = bindMountSource(mount);
      if (source) sources.push(source);
    }
  }
  return sources;
}

function volumeSource(value) {
  const source = value.split(":")[0] || "";
  return filesystemPathFromArg(source);
}

function bindMountSource(value) {
  const fields = keyValueFields(value);
  if (fields.type && fields.type !== "bind") return "";
  return filesystemPathFromArg(fields.source || fields.src || "");
}

function keyValueFields(value) {
  const fields = {};
  for (const part of value.split(",")) {
    const equalIndex = part.indexOf("=");
    if (equalIndex === -1) continue;
    const key = part.slice(0, equalIndex).trim().toLowerCase();
    const fieldValue = part.slice(equalIndex + 1).trim();
    if (key && fieldValue) {
      fields[key] = fieldValue;
    }
  }
  return fields;
}

function optionValue(arg, options) {
  for (const option of options) {
    if (arg.startsWith(`${option}=`)) {
      return arg.slice(option.length + 1);
    }
  }
  return "";
}

async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}
