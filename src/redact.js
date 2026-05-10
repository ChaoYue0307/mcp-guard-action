const SECRET_NAME_PATTERN = /(api[_-]?key|token|secret|password|passwd|private[_-]?key|client[_-]?secret|access[_-]?key|auth|credential|session|jwt|bearer|oauth)/i;

export function isSecretLikeName(name) {
  return SECRET_NAME_PATTERN.test(name);
}

export function redactValue(value) {
  if (!value) return "<empty>";
  const text = String(value);
  if (looksLikeVariableReference(text)) {
    return text;
  }
  if (text.length <= 8) {
    return "<redacted>";
  }
  return `${text.slice(0, 3)}...${text.slice(-3)} (${text.length} chars)`;
}

export function redactEnv(env) {
  return Object.fromEntries(
    Object.entries(env).map(([key, value]) => [key, isSecretLikeName(key) ? redactValue(value) : "<set>"])
  );
}

function looksLikeVariableReference(value) {
  return /^\$\{?[A-Z0-9_]+\}?$/i.test(value);
}

