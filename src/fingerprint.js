import path from "node:path";

export function findingFingerprint(finding, cwd) {
  const parts = [
    finding.id,
    displayPath(finding.configPath, cwd),
    finding.serverName,
    finding.title,
    finding.evidence
  ];

  return `mcpg_${stableHash(parts.join("\n"))}`;
}

export function displayPath(filePath, cwd) {
  if (!filePath || !cwd) return filePath;
  const resolvedCwd = path.resolve(cwd);
  const resolvedFile = path.resolve(filePath);
  if (resolvedFile === resolvedCwd) return ".";
  if (resolvedFile.startsWith(`${resolvedCwd}${path.sep}`)) {
    return resolvedFile.slice(resolvedCwd.length + 1);
  }
  return filePath;
}

export function stableHash(value) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}
