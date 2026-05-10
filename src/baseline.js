import fs from "node:fs/promises";
import path from "node:path";
import { displayPath } from "./fingerprint.js";
import { sortFindings } from "./severity.js";

export const BASELINE_VERSION = 1;

export async function loadBaselineFile(filePath) {
  let content;
  try {
    content = await fs.readFile(filePath, "utf8");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Could not read baseline file ${filePath}: ${message}`);
  }

  try {
    return normalizeBaseline(JSON.parse(content));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid baseline file ${filePath}: ${message}`);
  }
}

export async function writeBaselineFile(filePath, result, options = {}) {
  const baseline = createBaseline(result, options);
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, `${JSON.stringify(baseline, null, 2)}\n`, "utf8");
  return baseline;
}

export function createBaseline(result, { reason = "Accepted current MCP findings" } = {}) {
  const generatedAt = new Date().toISOString();
  const cwd = result.metadata.cwd;
  const findings = collectFindings(result).map((finding) => ({
    fingerprint: finding.fingerprint,
    id: finding.id,
    severity: finding.severity,
    serverName: finding.serverName,
    configPath: displayPath(finding.configPath, cwd),
    title: finding.title,
    evidence: finding.evidence,
    acceptedAt: generatedAt,
    reason
  }));

  return {
    version: BASELINE_VERSION,
    generatedAt,
    toolVersion: result.metadata.toolVersion,
    description: "mcp-guard baseline. Findings listed here are accepted known risks; new matching-unseen findings still fail CI.",
    findings
  };
}

export function applyBaseline(result, baseline, { baselinePath = "" } = {}) {
  const entriesByFingerprint = new Map(baseline.entries.map((entry) => [entry.fingerprint, entry]));
  const matchedFingerprints = new Set();
  const activeFindings = [];
  const acceptedFindings = [];

  for (const finding of result.findings) {
    const entry = entriesByFingerprint.get(finding.fingerprint);
    if (!entry) {
      activeFindings.push({ ...finding, status: "active" });
      continue;
    }

    matchedFingerprints.add(finding.fingerprint);
    acceptedFindings.push({
      ...finding,
      status: "accepted",
      acceptedAt: entry.acceptedAt || "",
      acceptedReason: entry.reason || ""
    });
  }

  return {
    ...result,
    findings: sortFindings(activeFindings),
    acceptedFindings: sortFindings(acceptedFindings),
    summary: summarize(sortFindings(activeFindings), result.servers, result.scannedFiles, acceptedFindings.length),
    baseline: {
      enabled: true,
      path: baselinePath ? displayPath(baselinePath, result.metadata.cwd) : "",
      version: baseline.version,
      fingerprintCount: baseline.entries.length,
      matchedFindingCount: matchedFingerprints.size,
      acceptedFindingCount: acceptedFindings.length,
      activeFindingCount: activeFindings.length,
      unmatchedEntryCount: baseline.entries.length - matchedFingerprints.size
    }
  };
}

export function summarize(findings, servers, scannedFiles, acceptedFindingCount = 0) {
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };

  for (const finding of findings) {
    if (counts[finding.severity] != null) {
      counts[finding.severity] += 1;
    }
  }

  return {
    scannedFileCount: scannedFiles.length,
    serverCount: servers.length,
    findingCount: findings.length,
    activeFindingCount: findings.length,
    acceptedFindingCount,
    totalFindingCount: findings.length + acceptedFindingCount,
    counts,
    riskScore: counts.critical * 20 + counts.high * 10 + counts.medium * 4 + counts.low
  };
}

function normalizeBaseline(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("expected a JSON object");
  }

  const entries = [];
  if (Array.isArray(raw.fingerprints)) {
    for (const fingerprint of raw.fingerprints) {
      if (typeof fingerprint === "string" && fingerprint) {
        entries.push({ fingerprint });
      }
    }
  }

  if (Array.isArray(raw.findings)) {
    for (const finding of raw.findings) {
      if (typeof finding === "string" && finding) {
        entries.push({ fingerprint: finding });
      } else if (finding && typeof finding === "object" && typeof finding.fingerprint === "string" && finding.fingerprint) {
        entries.push({
          fingerprint: finding.fingerprint,
          reason: typeof finding.reason === "string" ? finding.reason : "",
          acceptedAt: typeof finding.acceptedAt === "string" ? finding.acceptedAt : ""
        });
      }
    }
  }

  const deduped = [...new Map(entries.map((entry) => [entry.fingerprint, entry])).values()];
  return {
    version: raw.version || BASELINE_VERSION,
    entries: deduped
  };
}

function collectFindings(result) {
  return sortFindings([
    ...(result.findings || []),
    ...(result.acceptedFindings || [])
  ]);
}
