export const SEVERITY = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

export function severityRank(severity) {
  return SEVERITY[severity] ?? 0;
}

export function compareSeverity(actual, thresholdRank) {
  return severityRank(actual) - thresholdRank;
}

export function sortFindings(findings) {
  return [...findings].sort((left, right) => {
    const severityDiff = severityRank(right.severity) - severityRank(left.severity);
    if (severityDiff !== 0) return severityDiff;
    return left.id.localeCompare(right.id);
  });
}

