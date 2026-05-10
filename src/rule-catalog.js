export const RULE_CATALOG = [
  {
    id: "MCP000",
    severity: "low",
    title: "No MCP config files found",
    detects: "No MCP config files were found in common project or user locations.",
    recommendation: "Pass --config when the MCP config lives outside default discovery paths."
  },
  {
    id: "MCP001",
    severity: "high",
    title: "Server has no command or URL",
    detects: "An MCP server entry has neither command nor url.",
    recommendation: "Remove the server or define an explicit command or URL with reviewed settings."
  },
  {
    id: "MCP002",
    severity: "medium",
    title: "Config has no MCP servers object",
    detects: "A config file does not contain an mcpServers or servers object.",
    recommendation: "Check that the file is the intended MCP config before relying on the scan."
  },
  {
    id: "MCP003",
    severity: "high",
    title: "Config cannot be parsed as JSON",
    detects: "A config file could not be parsed as JSON.",
    recommendation: "Fix the JSON syntax so the scanner and MCP client can read the same config."
  },
  {
    id: "MCP010",
    severity: "high/critical",
    title: "MCP server runs through a shell",
    detects: "Shell wrappers such as sh, bash, zsh, fish, PowerShell, or cmd, especially inline scripts.",
    recommendation: "Use a direct, pinned executable instead of a shell wrapper."
  },
  {
    id: "MCP011",
    severity: "high",
    title: "Interpreter eval mode is enabled",
    detects: "Interpreter eval flags such as node -e, python -c, ruby -e, or similar inline code execution.",
    recommendation: "Replace inline code with a reviewed package or checked-in script."
  },
  {
    id: "MCP020",
    severity: "medium",
    title: "Remote package runner is used",
    detects: "Remote package runners such as npx, uvx, bunx, pipx, or package-manager dlx commands.",
    recommendation: "Pin the package version and prefer a reviewed lockfile or vendored executable for sensitive tools."
  },
  {
    id: "MCP021",
    severity: "high",
    title: "Remote MCP package is not version pinned",
    detects: "Remote package execution without an exact package version.",
    recommendation: "Pin the package to an exact version such as package@1.2.3 and review updates before changing it."
  },
  {
    id: "MCP030",
    severity: "high",
    title: "Secret-like environment variable is exposed",
    detects: "Secret-like environment variable names or values passed into an MCP server.",
    recommendation: "Use least-privilege, short-lived credentials and dedicated service accounts."
  },
  {
    id: "MCP040",
    severity: "medium/high",
    title: "MCP server has a broad working directory",
    detects: "Broad working directories such as home, root, Desktop, Documents, or Downloads.",
    recommendation: "Run the server in a narrow project directory or sandbox with only the files it needs."
  },
  {
    id: "MCP041",
    severity: "medium/high",
    title: "MCP server argument grants broad filesystem access",
    detects: "Filesystem arguments that grant broad access to home, root, or sensitive user folders.",
    recommendation: "Replace broad filesystem paths with a dedicated project folder or read-only sandbox path."
  },
  {
    id: "MCP050",
    severity: "critical",
    title: "Command includes a dangerous operation",
    detects: "Dangerous command patterns such as rm -rf, sudo, chmod 777, force push, or curl-pipe-shell.",
    recommendation: "Remove dangerous startup operations and run setup steps manually after review."
  },
  {
    id: "MCP060",
    severity: "medium",
    title: "Remote MCP server URL is configured",
    detects: "Remote HTTP or HTTPS MCP server URLs.",
    recommendation: "Verify the provider, document data sent to the server, and keep an allowlist of approved endpoints."
  },
  {
    id: "MCP061",
    severity: "high",
    title: "Secret-like header is configured",
    detects: "Secret-like remote MCP headers such as authorization or API key headers.",
    recommendation: "Use scoped, short-lived credentials and avoid long-lived secrets in MCP config files."
  },
  {
    id: "MCP070",
    severity: "high",
    title: "Command is outside policy",
    detects: "An MCP server command that is not listed in allowedCommands.",
    recommendation: "Use an approved command or update policy only after review."
  },
  {
    id: "MCP071",
    severity: "high",
    title: "Remote package is outside policy",
    detects: "A remote MCP package that is not listed in allowedPackages.",
    recommendation: "Use an approved package or update policy only after package review."
  },
  {
    id: "MCP072",
    severity: "high",
    title: "Working directory is outside policy",
    detects: "A server working directory outside allowedDirectories.",
    recommendation: "Move the server into an approved workspace or update policy only after review."
  },
  {
    id: "MCP073",
    severity: "high",
    title: "Filesystem argument is outside policy",
    detects: "A filesystem argument outside allowedDirectories.",
    recommendation: "Limit filesystem arguments to approved directories or update policy only after review."
  },
  {
    id: "MCP074",
    severity: "high",
    title: "Remote MCP URL is outside policy",
    detects: "A remote MCP endpoint outside allowedRemoteUrls.",
    recommendation: "Use an approved endpoint or update policy only after remote provider review."
  }
];

export function generateRulesText(rules = RULE_CATALOG) {
  const lines = [];
  lines.push("mcp-guard rule reference");
  lines.push(`Rules: ${rules.length}`);
  lines.push("");
  for (const rule of rules) {
    lines.push(`- [${rule.severity.toUpperCase()}] ${rule.id} ${rule.title}`);
    lines.push(`  Detects: ${rule.detects}`);
    lines.push(`  Fix: ${rule.recommendation}`);
  }
  return `${lines.join("\n")}\n`;
}

export function generateRulesMarkdown(rules = RULE_CATALOG) {
  const lines = [];
  lines.push("# mcp-guard Rule Reference");
  lines.push("");
  lines.push("| Rule | Severity | Title | What it detects | Recommended response |");
  lines.push("| --- | --- | --- | --- | --- |");
  for (const rule of rules) {
    lines.push(`| ${cell(rule.id)} | ${cell(rule.severity)} | ${cell(rule.title)} | ${cell(rule.detects)} | ${cell(rule.recommendation)} |`);
  }
  lines.push("");
  return `${lines.join("\n")}`;
}

export function generateRulesJson(rules = RULE_CATALOG) {
  return `${JSON.stringify({ rules }, null, 2)}\n`;
}

function cell(value) {
  return String(value).replace(/\|/g, "\\|");
}
