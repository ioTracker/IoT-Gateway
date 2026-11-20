function buildHeaders(authHeader, authToken) {
  const headers = {
    "content-type": "application/json"
  };

  if (authHeader && authToken) {
    headers[authHeader] = authToken;
  }

  return headers;
}

function serializeError(error) {
  if (!(error instanceof Error)) {
    return { value: error };
  }

  return {
    name: error.name,
    message: error.message,
    code: error.code,
    errno: error.errno,
    syscall: error.syscall,
    hostname: error.hostname,
    address: error.address,
    port: error.port,
    stack: error.stack,
    cause: error.cause ? serializeError(error.cause) : undefined
  };
}

function hasErrorCode(error, code) {
  const seen = new Set();
  let current = error;

  while (current && typeof current === "object" && !seen.has(current)) {
    if (current.code === code) {
      return true;
    }

    seen.add(current);
    current = current.cause;
  }

  return false;
}

async function postJson(url, body, { timeoutMs, authHeader, authToken, method = "POST" } = {}) {
  const actualTimeoutMs = timeoutMs || 5000;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), actualTimeoutMs);

  try {
    let canRetryConnectionReset = true;

    while (true) {
      try {
        const response = await fetch(url, {
          method,
          headers: buildHeaders(authHeader, authToken),
          body: JSON.stringify(body),
          signal: controller.signal
        });

        const text = await response.text();
        let json;

        try {
          json = text ? JSON.parse(text) : {};
        } catch (error) {
          json = { raw: text };
        }

        if (!response.ok) {
          const responseError = new Error(`Request to ${url} failed with status ${response.status}${text ? `: ${text}` : ""}`);
          responseError.code = "HTTP_RESPONSE_ERROR";
          responseError.statusCode = response.status;
          throw responseError;
        }

        return json;
      } catch (error) {
        if (canRetryConnectionReset && !controller.signal.aborted && hasErrorCode(error, "ECONNRESET")) {
          canRetryConnectionReset = false;
          continue;
        }

        throw error;
      }
    }
  } catch (error) {
    if (controller.signal.aborted) {
      const timeoutError = new Error(`Request to ${url} timed out after ${actualTimeoutMs}ms`);
      timeoutError.code = "HTTP_REQUEST_TIMEOUT";
      timeoutError.cause = error;
      throw timeoutError;
    }

    if (error instanceof Error && !error.message.startsWith(`Request to ${url}`)) {
      const requestError = new Error(`Request to ${url} failed: ${error.message}`);
      requestError.code = "HTTP_REQUEST_FAILED";
      requestError.cause = error;
      throw requestError;
    }

    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

module.exports = {
  postJson,
  serializeError,
  hasErrorCode
};
