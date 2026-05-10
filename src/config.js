import fs from "node:fs/promises";

export async function loadConfigFile(filePath) {
  const content = await fs.readFile(filePath, "utf8");
  try {
    return JSON.parse(content);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid JSON: ${message}`);
  }
}

export function extractServers(config, configPath) {
  const serversBlock = config?.mcpServers ?? config?.servers;
  if (!serversBlock || typeof serversBlock !== "object" || Array.isArray(serversBlock)) {
    return [];
  }

  return Object.entries(serversBlock).map(([name, raw]) => normalizeServer(name, raw, configPath));
}

function normalizeServer(name, raw, configPath) {
  const server = raw && typeof raw === "object" ? raw : {};
  return {
    name,
    configPath,
    command: normalizeString(server.command),
    args: normalizeArgs(server.args),
    env: normalizeEnv(server.env),
    cwd: normalizeString(server.cwd),
    url: normalizeString(server.url),
    headers: normalizeEnv(server.headers),
    raw: server
  };
}

function normalizeString(value) {
  return typeof value === "string" ? value : "";
}

function normalizeArgs(value) {
  if (Array.isArray(value)) {
    return value.map((item) => String(item));
  }
  if (typeof value === "string") {
    return [value];
  }
  return [];
}

function normalizeEnv(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }

  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [key, item == null ? "" : String(item)])
  );
}

