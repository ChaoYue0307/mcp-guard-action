import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export async function discoverConfigFiles({ cwd, env }) {
  const home = env.HOME || env.USERPROFILE || os.homedir();
  const candidates = uniquePaths([
    ...projectConfigCandidates(cwd),
    path.join(home, ".cursor", "mcp.json"),
    path.join(home, "Library", "Application Support", "Code", "User", "mcp.json"),
    path.join(home, "Library", "Application Support", "Code - Insiders", "User", "mcp.json"),
    path.join(home, "AppData", "Roaming", "Code", "User", "mcp.json"),
    path.join(home, "AppData", "Roaming", "Code - Insiders", "User", "mcp.json"),
    path.join(home, ".config", "Code", "User", "mcp.json"),
    path.join(home, ".config", "Code - Insiders", "User", "mcp.json"),
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

function projectConfigCandidates(cwd) {
  return ancestorDirs(cwd).flatMap((directory) => [
    path.join(directory, ".mcp.json"),
    path.join(directory, "mcp.json"),
    path.join(directory, ".cursor", "mcp.json"),
    path.join(directory, ".vscode", "mcp.json")
  ]);
}

function ancestorDirs(cwd) {
  const directories = [];
  let current = path.resolve(cwd);
  while (true) {
    directories.push(current);
    const parent = path.dirname(current);
    if (parent === current) return directories;
    current = parent;
  }
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
