import fs from "node:fs/promises";
import path from "node:path";

export const DEFAULT_POLICY_FILE = ".mcp-guard-policy.json";

export async function loadPolicy({ cwd, home, policyPath = "", includePolicy = true }) {
  if (!includePolicy) return null;

  const explicit = Boolean(policyPath);
  const resolvedPath = explicit ? resolvePolicyPath(policyPath, cwd) : path.join(cwd, DEFAULT_POLICY_FILE);

  if (!explicit && !(await fileExists(resolvedPath))) {
    return null;
  }

  let raw;
  try {
    raw = JSON.parse(await fs.readFile(resolvedPath, "utf8"));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid policy file ${resolvedPath}: ${message}`);
  }

  return normalizePolicy(raw, resolvedPath, { cwd, home });
}

export function policyForReport(policy) {
  if (!policy) return null;
  return {
    path: policy.path,
    version: policy.version,
    allowedCommands: [...policy.allowedCommands],
    allowedPackages: [...policy.allowedPackages],
    allowedDirectories: [...policy.allowedDirectories],
    allowedRemoteUrls: [...policy.allowedRemoteUrls]
  };
}

function normalizePolicy(raw, policyPath, context) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("Policy must be a JSON object.");
  }

  const allowedCommands = stringArray(raw.allowedCommands, "allowedCommands")
    .map((command) => path.basename(command).toLowerCase());
  const allowedPackages = stringArray(raw.allowedPackages, "allowedPackages")
    .map(packageIdentity);
  const allowedDirectories = stringArray(raw.allowedDirectories, "allowedDirectories");
  const allowedRemoteUrls = stringArray(raw.allowedRemoteUrls, "allowedRemoteUrls")
    .map(normalizePolicyUrl);

  return {
    path: policyPath,
    version: raw.version || 1,
    allowedCommands: new Set(allowedCommands),
    allowedPackages: new Set(allowedPackages),
    allowedDirectories,
    allowedDirectoryPaths: allowedDirectories.map((directory) => normalizePolicyPath(directory, context)),
    allowedRemoteUrls,
    raw: raw
  };
}

function stringArray(value, fieldName) {
  if (value == null) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || item.trim() === "")) {
    throw new Error(`${fieldName} must be an array of non-empty strings.`);
  }
  return value.map((item) => item.trim());
}

function packageIdentity(packageName) {
  if (packageName.startsWith("@")) {
    const secondAt = packageName.indexOf("@", 1);
    return secondAt > 1 ? packageName.slice(0, secondAt) : packageName;
  }
  const at = packageName.lastIndexOf("@");
  return at > 0 ? packageName.slice(0, at) : packageName;
}

function normalizePolicyPath(value, context) {
  if (value === "~") return path.normalize(context.home);
  if (value.startsWith("~/")) return path.join(context.home, value.slice(2));
  if (path.isAbsolute(value)) return path.normalize(value);
  return path.resolve(context.cwd, value);
}

function normalizePolicyUrl(value) {
  try {
    const parsed = new URL(value);
    const pathname = parsed.pathname === "/" ? "" : parsed.pathname.replace(/\/+$/, "");
    return `${parsed.origin}${pathname}`;
  } catch {
    throw new Error(`allowedRemoteUrls contains an invalid URL: ${value}`);
  }
}

function resolvePolicyPath(value, cwd) {
  return path.isAbsolute(value) ? value : path.resolve(cwd, value);
}

async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}
