import path from "node:path";
import { isSecretLikeName, redactValue } from "./redact.js";

const SHELL_COMMANDS = new Set(["sh", "bash", "zsh", "fish", "pwsh", "powershell", "cmd", "cmd.exe"]);
const EVAL_COMMANDS = new Set(["node", "python", "python3", "ruby", "perl", "php", "deno", "bun"]);
const REMOTE_EXEC_COMMANDS = new Set(["npx", "bunx", "uvx", "pipx"]);
const PACKAGE_MANAGER_COMMANDS = new Set(["npm", "pnpm", "yarn"]);
const BROAD_DIR_NAMES = new Set(["Desktop", "Documents", "Downloads"]);

export function evaluateServer(server, context) {
  const findings = [];

  if (!server.command && !server.url) {
    findings.push(finding({
      id: "MCP001",
      severity: "high",
      title: "Server has no command or URL",
      server,
      evidence: "This MCP server entry cannot be executed or audited reliably.",
      recommendation: "Remove the server or define an explicit command/url with a reviewed configuration."
    }));
  }

  findings.push(...ruleShellExecution(server));
  findings.push(...ruleEvalExecution(server));
  findings.push(...ruleRemotePackageExecution(server));
  findings.push(...ruleUnpinnedPackage(server));
  findings.push(...ruleSecretEnvironment(server));
  findings.push(...ruleBroadWorkingDirectory(server, context));
  findings.push(...ruleBroadFilesystemArgs(server, context));
  findings.push(...ruleDangerousCommandPattern(server));
  findings.push(...ruleRemoteUrl(server));
  findings.push(...ruleHeaders(server));
  findings.push(...rulePolicyAllowedCommand(server, context));
  findings.push(...rulePolicyAllowedPackage(server, context));
  findings.push(...rulePolicyAllowedWorkingDirectory(server, context));
  findings.push(...rulePolicyAllowedFilesystemArgs(server, context));
  findings.push(...rulePolicyAllowedRemoteUrl(server, context));

  return findings;
}

function ruleShellExecution(server) {
  const command = commandBase(server.command);
  if (!SHELL_COMMANDS.has(command)) return [];

  const hasInlineScript = server.args.some((arg) => arg === "-c" || arg === "/c");
  return [finding({
    id: "MCP010",
    severity: hasInlineScript ? "critical" : "high",
    title: hasInlineScript ? "Shell command executes inline script" : "MCP server runs through a shell",
    server,
    evidence: `command=${server.command} args=${server.args.join(" ")}`,
    recommendation: "Use a direct, pinned executable instead of a shell wrapper. If a shell is required, place the script in source control and review it."
  })];
}

function ruleEvalExecution(server) {
  const command = commandBase(server.command);
  if (!EVAL_COMMANDS.has(command)) return [];

  const evalFlag = server.args.find((arg) => ["-e", "-c", "--eval"].includes(arg));
  if (!evalFlag) return [];

  return [finding({
    id: "MCP011",
    severity: "high",
    title: "Interpreter eval mode is enabled",
    server,
    evidence: `command=${server.command} uses ${evalFlag}`,
    recommendation: "Replace inline code with a reviewed package or checked-in script."
  })];
}

function ruleRemotePackageExecution(server) {
  const command = commandBase(server.command);
  const firstArg = firstPackageArg(server.args);
  const usesDlx = PACKAGE_MANAGER_COMMANDS.has(command) && server.args[0] === "dlx";
  if (!REMOTE_EXEC_COMMANDS.has(command) && !usesDlx) return [];

  return [finding({
    id: "MCP020",
    severity: "medium",
    title: "MCP server is launched through a remote package runner",
    server,
    evidence: `command=${server.command} package=${firstArg || "<unknown>"}`,
    recommendation: "Pin the package version, review the package source, and prefer a local lockfile or vendored executable for sensitive tools."
  })];
}

function ruleUnpinnedPackage(server) {
  const command = commandBase(server.command);
  const usesRemoteRunner = REMOTE_EXEC_COMMANDS.has(command) || (PACKAGE_MANAGER_COMMANDS.has(command) && server.args[0] === "dlx");
  if (!usesRemoteRunner) return [];

  const packageArg = firstPackageArg(server.args);
  if (!packageArg || isPinnedPackage(packageArg)) return [];

  return [finding({
    id: "MCP021",
    severity: "high",
    title: "Remote MCP package is not version pinned",
    server,
    evidence: `package=${packageArg}`,
    recommendation: "Pin the package to an exact version such as package@1.2.3 and review updates before changing it."
  })];
}

function ruleSecretEnvironment(server) {
  const findings = [];
  for (const [key, value] of Object.entries(server.env)) {
    if (!isSecretLikeName(key)) continue;
    findings.push(finding({
      id: "MCP030",
      severity: "high",
      title: "Secret-like environment variable is exposed to MCP server",
      server,
      evidence: `${key}=${redactValue(value)}`,
      recommendation: "Pass the least privileged token possible. Prefer scoped tokens, short-lived credentials, and a dedicated service account."
    }));
  }
  return findings;
}

function ruleBroadWorkingDirectory(server, context) {
  if (!server.cwd) return [];

  const normalized = normalizePath(server.cwd, context);
  const home = normalizePath(context.home, context);
  const isHome = normalized === home;
  const isRoot = normalized === path.parse(normalized).root;
  const isSensitiveHomeChild = BROAD_DIR_NAMES.has(path.basename(normalized));

  if (!isHome && !isRoot && !isSensitiveHomeChild) return [];

  return [finding({
    id: "MCP040",
    severity: isRoot || isHome ? "high" : "medium",
    title: "MCP server has a broad working directory",
    server,
    evidence: `cwd=${server.cwd}`,
    recommendation: "Run the server in a narrow project directory or sandbox with only the files it needs."
  })];
}

function ruleBroadFilesystemArgs(server, context) {
  const findings = [];
  const home = normalizePath(context.home, context);

  for (const arg of server.args) {
    const value = valueFromArg(arg);
    if (!value) continue;

    const normalized = normalizePath(value, context);
    const base = path.basename(normalized);
    const isRoot = normalized === path.parse(normalized).root;
    const isHome = normalized === home;
    const isHomePrefix = normalized.startsWith(`${home}${path.sep}`) && normalized.split(path.sep).length <= home.split(path.sep).length + 2;
    const isSensitiveHomeChild = BROAD_DIR_NAMES.has(base);

    if (isRoot || isHome || isHomePrefix || isSensitiveHomeChild || value === "~") {
      findings.push(finding({
        id: "MCP041",
        severity: isRoot || isHome ? "high" : "medium",
        title: "MCP server argument grants broad filesystem access",
        server,
        evidence: `arg=${arg}`,
        recommendation: "Replace broad filesystem paths with a dedicated project folder or read-only sandbox path."
      }));
    }
  }

  return findings;
}

function ruleDangerousCommandPattern(server) {
  const joined = [server.command, ...server.args].join(" ");
  const patterns = [
    { pattern: /\brm\s+-rf\b/, label: "rm -rf" },
    { pattern: /\bsudo\b/, label: "sudo" },
    { pattern: /\bchmod\s+777\b/, label: "chmod 777" },
    { pattern: /\bgit\s+push\s+--force\b/, label: "git push --force" },
    { pattern: /\bcurl\b.*\|\s*(sh|bash|zsh)\b/, label: "curl pipe to shell" },
    { pattern: /\bwget\b.*\|\s*(sh|bash|zsh)\b/, label: "wget pipe to shell" }
  ];

  return patterns
    .filter(({ pattern }) => pattern.test(joined))
    .map(({ label }) => finding({
      id: "MCP050",
      severity: "critical",
      title: "MCP server command includes a dangerous operation",
      server,
      evidence: label,
      recommendation: "Remove the dangerous operation from MCP startup. Run destructive setup steps manually and review them separately."
    }));
}

function ruleRemoteUrl(server) {
  if (!server.url || !/^https?:\/\//i.test(server.url)) return [];

  return [finding({
    id: "MCP060",
    severity: "medium",
    title: "Remote MCP server URL is configured",
    server,
    evidence: `url=${server.url}`,
    recommendation: "Verify the provider, use HTTPS, document the data sent to this server, and keep an allowlist of approved remote endpoints."
  })];
}

function ruleHeaders(server) {
  const findings = [];
  for (const [key, value] of Object.entries(server.headers)) {
    if (!isSecretLikeName(key) && !isSecretLikeName(value)) continue;
    findings.push(finding({
      id: "MCP061",
      severity: "high",
      title: "Secret-like header is configured for remote MCP server",
      server,
      evidence: `${key}=${redactValue(value)}`,
      recommendation: "Use scoped, short-lived credentials and avoid placing long-lived secrets directly in MCP config files."
    }));
  }
  return findings;
}

function rulePolicyAllowedCommand(server, context) {
  const policy = context.policy;
  if (!policy || policy.allowedCommands.size === 0 || !server.command) return [];

  const command = commandBase(server.command);
  if (policy.allowedCommands.has(command)) return [];

  return [finding({
    id: "MCP070",
    severity: "high",
    title: "MCP server command is not allowed by policy",
    server,
    evidence: `command=${server.command} allowed=${listSet(policy.allowedCommands)}`,
    recommendation: "Use an approved command, or add this command to allowedCommands only after review."
  })];
}

function rulePolicyAllowedPackage(server, context) {
  const policy = context.policy;
  if (!policy || policy.allowedPackages.size === 0) return [];

  const command = commandBase(server.command);
  const usesRemoteRunner = REMOTE_EXEC_COMMANDS.has(command) || (PACKAGE_MANAGER_COMMANDS.has(command) && server.args[0] === "dlx");
  if (!usesRemoteRunner) return [];

  const packageArg = firstPackageArg(server.args);
  if (!packageArg) return [];

  const packageName = packageIdentity(packageArg);
  if (policy.allowedPackages.has(packageName)) return [];

  return [finding({
    id: "MCP071",
    severity: "high",
    title: "Remote MCP package is not allowed by policy",
    server,
    evidence: `package=${packageName} allowed=${listSet(policy.allowedPackages)}`,
    recommendation: "Use an approved MCP package, or add this package to allowedPackages only after review."
  })];
}

function rulePolicyAllowedWorkingDirectory(server, context) {
  const policy = context.policy;
  if (!policy || policy.allowedDirectoryPaths.length === 0 || !server.cwd) return [];

  const normalized = normalizePath(server.cwd, context);
  if (isAllowedPath(normalized, policy.allowedDirectoryPaths)) return [];

  return [finding({
    id: "MCP072",
    severity: "high",
    title: "MCP server working directory is outside policy",
    server,
    evidence: `cwd=${server.cwd} allowed=${policy.allowedDirectories.join(", ")}`,
    recommendation: "Move this server into an approved workspace directory, or add the directory to allowedDirectories after review."
  })];
}

function rulePolicyAllowedFilesystemArgs(server, context) {
  const policy = context.policy;
  if (!policy || policy.allowedDirectoryPaths.length === 0) return [];

  const findings = [];
  for (const arg of server.args) {
    const value = filesystemPathFromArg(arg);
    if (!value) continue;

    const normalized = normalizePath(value, context);
    if (isAllowedPath(normalized, policy.allowedDirectoryPaths)) continue;

    findings.push(finding({
      id: "MCP073",
      severity: "high",
      title: "MCP server filesystem argument is outside policy",
      server,
      evidence: `arg=${arg} allowed=${policy.allowedDirectories.join(", ")}`,
      recommendation: "Limit filesystem arguments to approved directories, or update allowedDirectories only after review."
    }));
  }
  return findings;
}

function rulePolicyAllowedRemoteUrl(server, context) {
  const policy = context.policy;
  if (!policy || policy.allowedRemoteUrls.length === 0 || !server.url) return [];
  if (isAllowedRemoteUrl(server.url, policy.allowedRemoteUrls)) return [];

  return [finding({
    id: "MCP074",
    severity: "high",
    title: "Remote MCP URL is not allowed by policy",
    server,
    evidence: `url=${server.url} allowed=${policy.allowedRemoteUrls.join(", ")}`,
    recommendation: "Use an approved remote MCP endpoint, or add this URL to allowedRemoteUrls only after review."
  })];
}

function finding({ id, severity, title, server, evidence, recommendation }) {
  return {
    id,
    severity,
    title,
    serverName: server.name,
    configPath: server.configPath,
    evidence,
    recommendation
  };
}

function commandBase(command) {
  if (!command) return "";
  return path.basename(command).toLowerCase();
}

function firstPackageArg(args) {
  const cleaned = args.filter((arg) => arg && !arg.startsWith("-"));
  if (cleaned[0] === "dlx") return cleaned[1] || "";
  return cleaned[0] || "";
}

function isPinnedPackage(packageName) {
  if (packageName.startsWith("@")) {
    const secondAt = packageName.indexOf("@", 1);
    return secondAt > 1 && secondAt < packageName.length - 1;
  }
  const at = packageName.lastIndexOf("@");
  return at > 0 && at < packageName.length - 1;
}

function packageIdentity(packageName) {
  if (packageName.startsWith("@")) {
    const secondAt = packageName.indexOf("@", 1);
    return secondAt > 1 ? packageName.slice(0, secondAt) : packageName;
  }
  const at = packageName.lastIndexOf("@");
  return at > 0 ? packageName.slice(0, at) : packageName;
}

function valueFromArg(arg) {
  if (!arg) return "";
  const equalIndex = arg.indexOf("=");
  if (equalIndex > -1) return arg.slice(equalIndex + 1);
  if (arg.startsWith("/") || arg.startsWith("~")) return arg;
  return "";
}

function filesystemPathFromArg(arg) {
  const value = valueFromArg(arg);
  if (!value) return "";
  if (value === "~" || value.startsWith("~/")) return value;
  if (value.startsWith("/") || value.startsWith("./") || value.startsWith("../")) return value;
  return "";
}

function normalizePath(value, context) {
  if (!value) return "";
  if (value === "~") return context.home;
  if (value.startsWith("~/")) return path.join(context.home, value.slice(2));
  if (path.isAbsolute(value)) return path.normalize(value);
  return path.resolve(context.cwd, value);
}

function isAllowedPath(filePath, allowedPaths) {
  return allowedPaths.some((allowedPath) => {
    const normalizedAllowed = path.normalize(allowedPath);
    return filePath === normalizedAllowed || filePath.startsWith(`${normalizedAllowed}${path.sep}`);
  });
}

function isAllowedRemoteUrl(value, allowedUrls) {
  let target;
  try {
    target = new URL(value);
  } catch {
    return false;
  }

  const targetPath = target.pathname === "/" ? "" : target.pathname.replace(/\/+$/, "");
  const targetValue = `${target.origin}${targetPath}`;
  return allowedUrls.some((allowed) => targetValue === allowed || targetValue.startsWith(`${allowed}/`));
}

function listSet(items) {
  return [...items].join(", ");
}
