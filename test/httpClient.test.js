const test = require("node:test");
const assert = require("node:assert/strict");
const { postJson, serializeError } = require("../src/httpClient");

test("postJson reports outbound request timeout with endpoint context", async () => {
  const originalFetch = global.fetch;
  global.fetch = async (url, options) => new Promise((resolve, reject) => {
    options.signal.addEventListener("abort", () => {
      reject(new DOMException("This operation was aborted", "AbortError"));
    });
  });

  try {
    await assert.rejects(
      postJson("https://example.test/forward", { deviceId: "00001111" }, { timeoutMs: 1 }),
      (error) => {
        assert.equal(error.message, "Request to https://example.test/forward timed out after 1ms");
        assert.equal(error.code, "HTTP_REQUEST_TIMEOUT");
        assert.equal(error.cause.name, "AbortError");
        return true;
      }
    );
  } finally {
    global.fetch = originalFetch;
  }
});

test("postJson reports outbound fetch failures with endpoint context", async () => {
  const originalFetch = global.fetch;
  let requestCount = 0;
  global.fetch = async () => {
    requestCount += 1;
    const networkError = new Error("socket hang up");
    networkError.code = "ECONNRESET";
    throw new TypeError("fetch failed", { cause: networkError });
  };

  try {
    await assert.rejects(
      postJson("https://example.test/config", { deviceId: "00001111" }, { timeoutMs: 5000 }),
      (error) => {
        assert.equal(error.message, "Request to https://example.test/config failed: fetch failed");
        assert.equal(error.code, "HTTP_REQUEST_FAILED");
        assert.equal(error.cause.name, "TypeError");
        assert.equal(requestCount, 2);
        const details = serializeError(error);
        assert.equal(details.cause.cause.code, "ECONNRESET");
        assert.equal(details.cause.cause.message, "socket hang up");
        return true;
      }
    );
  } finally {
    global.fetch = originalFetch;
  }
});

test("postJson retries once after an ECONNRESET", async () => {
  const originalFetch = global.fetch;
  let requestCount = 0;
  global.fetch = async () => {
    requestCount += 1;

    if (requestCount === 1) {
      const networkError = new Error("socket hang up");
      networkError.code = "ECONNRESET";
      throw new TypeError("fetch failed", { cause: networkError });
    }

    return new Response(JSON.stringify({ accepted: true }));
  };

  try {
    const response = await postJson("https://example.test/forward", { deviceId: "00001111" });
    assert.deepEqual(response, { accepted: true });
    assert.equal(requestCount, 2);
  } finally {
    global.fetch = originalFetch;
  }
});
