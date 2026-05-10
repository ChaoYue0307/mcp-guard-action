import os from "node:os";
import path from "node:path";
import { extractServers, loadConfigFile } from "./config.js";
import { discoverConfigFiles } from "./discovery.js";
import { findingFingerprint } from "./fingerprint.js";
import { evaluateServer } from "./rules.js";
import { sortFindings } from "./severity.js";
import { summarize } from "./baseline.js";

export async function scan({ cwd, env, configPaths = [], includeDefaults = true, toolVersion = "0.0.0" }) {
  const home = env.HOME || env.USERPROFILE || os.homedir();
  const explicitPaths = configPaths.map((item) => path.resolve(item));
  const shouldDiscover = explicitPaths.length === 0 && includeDefaults;
  const discoveredPaths = shouldDiscover ? await discoverConfigFiles({ cwd, env }) : [];
  const pathsToScan = uniquePaths([...explicitPaths, ...discoveredPaths]);

  const servers = [];
  const findings = [];
  const scannedFiles = [];

  if (pathsToScan.length === 0) {
    findings.push({
      id: "MCP000",
      severity: "low",
      title: "No MCP config files found",
      serverName: "<workspace>",
      configPath: cwd,
      evidence: "mcp-guard checked common Claude Desktop, Cursor, and project config paths.",
      recommendation: "Pass --config path/to/mcp.json if your configuration lives elsewhere."
    });
  }

  for (const configPath of pathsToScan) {
    scannedFiles.push(configPath);
    try {
      const config = await loadConfigFile(configPath);
      const extracted = extractServers(config, configPath);
      servers.push(...extracted);

      if (extracted.length === 0) {
        findings.push({
          id: "MCP002",
          severity: "medium",
          title: "Config file has no MCP servers",
          serverName: "<config>",
          configPath,
          evidence: "Expected an object at mcpServers or servers.",
          recommendation: "Check whether this is the right file or update the config schema."
        });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      findings.push({
        id: "MCP003",
        severity: "high",
        title: "Config file could not be parsed",
        serverName: "<config>",
        configPath,
        evidence: message,
        recommendation: "Fix the JSON syntax or remove the invalid config from the scan."
      });
    }
  }

  for (const server of servers) {
    findings.push(...evaluateServer(server, { cwd, home }));
  }

  const sortedFindings = sortFindings(findings).map((finding) => ({
    ...finding,
    fingerprint: findingFingerprint(finding, cwd),
    status: "active"
  }));
  return {
    metadata: {
      generatedAt: new Date().toISOString(),
      cwd,
      home,
      toolVersion
    },
    scannedFiles,
    servers,
    findings: sortedFindings,
    acceptedFindings: [],
    summary: summarize(sortedFindings, servers, scannedFiles)
  };
}

function uniquePaths(paths) {
  return [...new Set(paths.map((item) => path.resolve(item)))];
}
