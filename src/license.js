const DEFAULT_PRODUCT = "pro-monthly";
const DEFAULT_TIMEOUT_MS = 10000;

export function normalizeLicenseOptions(options = {}, env = {}) {
  const endpoint = options.endpoint || env.MCP_GUARD_LICENSE_ENDPOINT || "";
  const licenseKey = options.licenseKey || env.MCP_GUARD_LICENSE_KEY || "";
  const email = options.email || env.MCP_GUARD_LICENSE_EMAIL || "";
  const product = options.product || env.MCP_GUARD_LICENSE_PRODUCT || DEFAULT_PRODUCT;
  const timeoutMs = Number(options.timeoutMs || env.MCP_GUARD_LICENSE_TIMEOUT_MS || DEFAULT_TIMEOUT_MS);

  return {
    endpoint,
    licenseKey,
    email,
    product,
    timeoutMs: Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : DEFAULT_TIMEOUT_MS
  };
}

export async function verifyRemoteLicense(options = {}) {
  const config = normalizeLicenseOptions(options);
  validateLicenseConfig(config);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), config.timeoutMs);

  try {
    const response = await (options.fetchImpl || fetch)(config.endpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json"
      },
      body: JSON.stringify({
        licenseKey: config.licenseKey,
        email: config.email,
        product: config.product
      }),
      signal: controller.signal
    });

    let body;
    try {
      body = await response.json();
    } catch {
      return {
        valid: false,
        error: "invalid_license_response",
        status: response.status
      };
    }

    if (!response.ok) {
      return {
        valid: false,
        error: body.error || `license_endpoint_${response.status}`,
        status: response.status
      };
    }

    if (body.valid === true) {
      return {
        valid: true,
        product: body.product || config.product,
        email: body.email || config.email,
        stripeSessionId: body.stripeSessionId || "",
        stripeSubscriptionId: body.stripeSubscriptionId || ""
      };
    }

    return {
      valid: false,
      error: body.error || "license_rejected",
      status: response.status
    };
  } catch (error) {
    return {
      valid: false,
      error: error?.name === "AbortError" ? "license_request_timeout" : "license_request_failed"
    };
  } finally {
    clearTimeout(timeout);
  }
}

export function validateLicenseConfig(config) {
  if (!config.endpoint) {
    throw new Error("license endpoint is required. Set --endpoint or MCP_GUARD_LICENSE_ENDPOINT.");
  }
  if (!config.licenseKey) {
    throw new Error("license key is required. Set --key or MCP_GUARD_LICENSE_KEY.");
  }
  if (!config.email) {
    throw new Error("license email is required. Set --email or MCP_GUARD_LICENSE_EMAIL.");
  }

  let url;
  try {
    url = new URL(config.endpoint);
  } catch {
    throw new Error("license endpoint must be a valid URL.");
  }

  if (url.protocol !== "https:" && !isLocalHttpEndpoint(url)) {
    throw new Error("license endpoint must use HTTPS, except for localhost testing.");
  }
}

function isLocalHttpEndpoint(url) {
  return url.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(url.hostname);
}
