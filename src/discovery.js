import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export async function discoverConfigFiles({ cwd, env }) {
  const home = env.HOME || env.USERPROFILE || os.homedir();
  const candidates = uniquePaths([
    path.join(cwd, ".mcp.json"),
    path.join(cwd, "mcp.json"),
    path.join(cwd, ".cursor", "mcp.json"),
    path.join(home, ".cursor", "mcp.json"),
    path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
    path.join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json"),
    path.join(home, ".config", "Claude", "claude_desktop_config.json"),
    path.join(home, ".config", "claude", "claude_desktop_config.json")
  ]);

  const found = [];
  for (const candidate of candidates) {
    if (await isReadableFile(candidate)) {
      found.push(candidate);
    }
  }
  return found;
}

async function isReadableFile(filePath) {
  try {
    const stat = await fs.stat(filePath);
    return stat.isFile();
  } catch {
    return false;
  }
}

function uniquePaths(paths) {
  return [...new Set(paths.map((item) => path.resolve(item)))];
}

