const test = require("node:test");
const assert = require("node:assert/strict");
const {
  fetchClientCredentialsToken,
  OAuthClientCredentialsService
} = require("../src/services/oauthClient");

test("fetchClientCredentialsToken requests and validates an access token", async () => {
  const originalFetch = global.fetch;
  let capturedUrl;
  let capturedOptions;

  global.fetch = async (url, options) => {
    capturedUrl = url;
    capturedOptions = options;

    return new Response(JSON.stringify({
      access_token: "access-token",
      token_type: "Bearer",
      expires_in: 3600
    }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };

  try {
    const token = await fetchClientCredentialsToken({
      tokenEndpoint: "https://example.test/oauth/token",
      clientId: "lte-server",
      clientSecret: "secret",
      timeoutMs: 5000
    });

    assert.deepEqual(token, {
      accessToken: "access-token",
      tokenType: "Bearer",
      expiresIn: 3600
    });
    assert.equal(capturedUrl, "https://example.test/oauth/token");
    assert.equal(capturedOptions.method, "POST");
    assert.equal(capturedOptions.headers["content-type"], "application/x-www-form-urlencoded");
    assert.equal(capturedOptions.body.toString(), "grant_type=client_credentials&client_id=lte-server&client_secret=secret");
  } finally {
    global.fetch = originalFetch;
  }
});

test("fetchClientCredentialsToken rejects responses without an access token", async () => {
  const originalFetch = global.fetch;

  global.fetch = async () => new Response(JSON.stringify({ token_type: "Bearer" }), {
    status: 200,
    headers: { "content-type": "application/json" }
  });

  try {
    await assert.rejects(
      fetchClientCredentialsToken({
        tokenEndpoint: "https://example.test/oauth/token",
        clientId: "lte-server",
        clientSecret: "secret",
        timeoutMs: 5000
      }),
      (error) => {
        assert.equal(error.message, "Token response from https://example.test/oauth/token did not include a string access_token");
        assert.equal(error.code, "OAUTH_TOKEN_INVALID_RESPONSE");
        return true;
      }
    );
  } finally {
    global.fetch = originalFetch;
  }
});

test("fetchClientCredentialsToken rejects responses without token expiration", async () => {
  const originalFetch = global.fetch;

  global.fetch = async () => new Response(JSON.stringify({
    access_token: "access-token",
    token_type: "Bearer"
  }), {
    status: 200,
    headers: { "content-type": "application/json" }
  });

  try {
    await assert.rejects(
      fetchClientCredentialsToken({
        tokenEndpoint: "https://example.test/oauth/token",
        clientId: "lte-server",
        clientSecret: "secret",
        timeoutMs: 5000
      }),
      (error) => {
        assert.equal(error.message, "Token response from https://example.test/oauth/token did not include a positive numeric expires_in");
        assert.equal(error.code, "OAUTH_TOKEN_INVALID_RESPONSE");
        return true;
      }
    );
  } finally {
    global.fetch = originalFetch;
  }
});

test("fetchClientCredentialsToken reports token endpoint errors with context", async () => {
  const originalFetch = global.fetch;

  global.fetch = async () => new Response(JSON.stringify({ error: "invalid_client" }), {
    status: 401,
    headers: { "content-type": "application/json" }
  });

  try {
    await assert.rejects(
      fetchClientCredentialsToken({
        tokenEndpoint: "https://example.test/oauth/token",
        clientId: "lte-server",
        clientSecret: "bad-secret",
        timeoutMs: 5000
      }),
      (error) => {
        assert.equal(
          error.message,
          'Token request to https://example.test/oauth/token failed with status 401: {"error":"invalid_client"}'
        );
        assert.equal(error.code, "OAUTH_TOKEN_RESPONSE_ERROR");
        assert.equal(error.statusCode, 401);
        return true;
      }
    );
  } finally {
    global.fetch = originalFetch;
  }
});

test("OAuthClientCredentialsService loads and exposes an access token", async () => {
  const originalFetch = global.fetch;
  const service = new OAuthClientCredentialsService({
    tokenEndpoint: "https://example.test/oauth/token",
    clientId: "lte-server",
    clientSecret: "secret",
    timeoutMs: 5000
  });

  global.fetch = async () => new Response(JSON.stringify({
    access_token: "loaded-token",
    token_type: "Bearer",
    expires_in: 3600
  }), {
    status: 200,
    headers: { "content-type": "application/json" }
  });

  try {
    await service.start();
    assert.equal(await service.getAccessToken(), "loaded-token");
    assert.equal(service.currentToken.expiresAtMs > Date.now(), true);
    assert.equal(service.currentToken.refreshAtMs < service.currentToken.expiresAtMs, true);
  } finally {
    service.stop();
    global.fetch = originalFetch;
  }
});

test("OAuthClientCredentialsService refreshes before returning when the token is expired", async () => {
  const originalFetch = global.fetch;
  const service = new OAuthClientCredentialsService({
    tokenEndpoint: "https://example.test/oauth/token",
    clientId: "lte-server",
    clientSecret: "secret",
    timeoutMs: 5000
  });

  service.currentToken = {
    accessToken: "expired-token",
    tokenType: "Bearer",
    expiresIn: 1,
    issuedAtMs: Date.now() - 2000,
    expiresAtMs: Date.now() - 1000,
    refreshAtMs: Date.now() - 1500
  };

  global.fetch = async () => new Response(JSON.stringify({
    access_token: "refreshed-token",
    token_type: "Bearer",
    expires_in: 3600
  }), {
    status: 200,
    headers: { "content-type": "application/json" }
  });

  try {
    assert.equal(await service.getAccessToken(), "refreshed-token");
  } finally {
    service.stop();
    global.fetch = originalFetch;
  }
});

test("OAuthClientCredentialsService returns a valid token while refreshing in the background", async () => {
  const originalFetch = global.fetch;
  const service = new OAuthClientCredentialsService({
    tokenEndpoint: "https://example.test/oauth/token",
    clientId: "lte-server",
    clientSecret: "secret",
    timeoutMs: 5000
  });
  let resolveFetch;
  let fetchCalled = false;

  service.currentToken = {
    accessToken: "current-token",
    tokenType: "Bearer",
    expiresIn: 3600,
    issuedAtMs: Date.now() - 3540000,
    expiresAtMs: Date.now() + 60000,
    refreshAtMs: Date.now() - 1000
  };

  global.fetch = async () => {
    fetchCalled = true;
    await new Promise((resolve) => {
      resolveFetch = resolve;
    });

    return new Response(JSON.stringify({
      access_token: "background-token",
      token_type: "Bearer",
      expires_in: 3600
    }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };

  try {
    assert.equal(await service.getAccessToken(), "current-token");
    assert.equal(fetchCalled, true);

    const refreshPromise = service.refreshPromise;
    resolveFetch();
    await refreshPromise;

    assert.equal(await service.getAccessToken(), "background-token");
  } finally {
    service.stop();
    global.fetch = originalFetch;
  }
});
