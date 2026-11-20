const test = require("node:test");
const assert = require("node:assert/strict");
const { HttpKeyProvider, DbKeyProvider } = require("../src/services/keyProvider");

function fakeAuthService(token = "access-token") {
  return {
    async getAccessToken() {
      return token;
    }
  };
}

test("HTTP key provider sends configured static auth header by default", async () => {
  const originalFetch = global.fetch;
  let capturedOptions;

  global.fetch = async (url, options) => {
    capturedOptions = options;
    return new Response(JSON.stringify({ key: "00112233445566778899AABBCCDDEEFF" }), { status: 200 });
  };

  try {
    const provider = new HttpKeyProvider({
      url: "https://api.example.test/devices/get-lte-keys",
      method: "POST",
      timeoutMs: 5000,
      authHeader: "x-api-key",
      authToken: "static-token",
      useDownlinkToken: false,
      deviceIdField: "hardwareId",
      responseKeyField: "key"
    }, {
      authService: fakeAuthService()
    });

    const key = await provider.getKey("00001111", {
      version: 1,
      imei: "123456789012345",
      iccid: "8944501234567890123",
      deviceVersions: {
        hwVersion: "00000001",
        stmVersion: "00000002",
        nrfVersion: "00000003",
        espVersion: "00000004",
        _raw: "00000001000000020000000300000004"
      }
    });

    assert.equal(key, "00112233445566778899AABBCCDDEEFF");
    assert.equal(capturedOptions.headers["x-api-key"], "static-token");
    assert.equal(capturedOptions.headers.Authorization, undefined);
    assert.deepEqual(JSON.parse(capturedOptions.body), {
      hardwareId: "00001111",
      metadata: {
        version: 1,
        imei: "123456789012345",
        iccid: "8944501234567890123",
        deviceVersions: {
          hwVersion: "00000001",
          stmVersion: "00000002",
          nrfVersion: "00000003",
          espVersion: "00000004",
          _raw: "00000001000000020000000300000004"
        }
      }
    });
  } finally {
    global.fetch = originalFetch;
  }
});

test("HTTP key provider can reuse the downlink OAuth bearer token", async () => {
  const originalFetch = global.fetch;
  let capturedOptions;

  global.fetch = async (url, options) => {
    capturedOptions = options;
    return new Response(JSON.stringify({ lteAesKey: "00112233445566778899AABBCCDDEEFF" }), { status: 200 });
  };

  try {
    const provider = new HttpKeyProvider({
      url: "https://api.example.test/devices/get-lte-keys",
      method: "POST",
      timeoutMs: 5000,
      authHeader: "x-api-key",
      authToken: "static-token",
      useDownlinkToken: true,
      deviceIdField: "hardwareId",
      responseKeyField: "lteAesKey"
    }, {
      authService: fakeAuthService("shared-token")
    });

    const key = await provider.getKey("00001111");

    assert.equal(key, "00112233445566778899AABBCCDDEEFF");
    assert.equal(capturedOptions.headers.Authorization, "Bearer shared-token");
    assert.equal(capturedOptions.headers["x-api-key"], undefined);
  } finally {
    global.fetch = originalFetch;
  }
});

test("HTTP key provider caches keys by device id", async () => {
  const originalFetch = global.fetch;
  let requestCount = 0;

  global.fetch = async () => {
    requestCount += 1;
    return new Response(JSON.stringify({ key: "00112233445566778899AABBCCDDEEFF" }), { status: 200 });
  };

  try {
    const provider = new HttpKeyProvider({
      url: "https://api.example.test/devices/get-lte-keys",
      method: "POST",
      timeoutMs: 5000,
      authHeader: "x-api-key",
      authToken: "static-token",
      useDownlinkToken: false,
      deviceIdField: "hardwareId",
      responseKeyField: "key"
    });

    const firstKey = await provider.getKey("00001111");
    const secondKey = await provider.getKey("00001111");

    assert.equal(firstKey, "00112233445566778899AABBCCDDEEFF");
    assert.equal(secondKey, "00112233445566778899AABBCCDDEEFF");
    assert.equal(requestCount, 1);
  } finally {
    global.fetch = originalFetch;
  }
});

test("HTTP key provider retries when a key load fails", async () => {
  const originalFetch = global.fetch;
  let requestCount = 0;

  global.fetch = async () => {
    requestCount += 1;
    return new Response(
      JSON.stringify(requestCount === 1 ? {} : { key: "00112233445566778899AABBCCDDEEFF" }),
      { status: 200 }
    );
  };

  try {
    const provider = new HttpKeyProvider({
      url: "https://api.example.test/devices/get-lte-keys",
      method: "POST",
      timeoutMs: 5000,
      authHeader: "x-api-key",
      authToken: "static-token",
      useDownlinkToken: false,
      deviceIdField: "hardwareId",
      responseKeyField: "key"
    });

    await assert.rejects(
      provider.getKey("00001111"),
      /Key service response did not include "key" \(deviceId = 00001111\)/
    );

    const key = await provider.getKey("00001111");

    assert.equal(key, "00112233445566778899AABBCCDDEEFF");
    assert.equal(requestCount, 2);
  } finally {
    global.fetch = originalFetch;
  }
});

test("DB key provider caches keys by device id", async () => {
  const provider = new DbKeyProvider({});
  let queryCount = 0;

  provider.queryKey = async (deviceId) => {
    queryCount += 1;
    return `key-for-${deviceId}`;
  };

  const firstKey = await provider.getKey("00001111");
  const secondKey = await provider.getKey("00001111");
  const otherKey = await provider.getKey("00002222");

  assert.equal(firstKey, "key-for-00001111");
  assert.equal(secondKey, "key-for-00001111");
  assert.equal(otherKey, "key-for-00002222");
  assert.equal(queryCount, 2);
});

test("HTTP key provider requires an auth service when downlink token reuse is enabled", async () => {
  const provider = new HttpKeyProvider({
    url: "https://api.example.test/devices/get-lte-keys",
    method: "POST",
    timeoutMs: 5000,
    authHeader: "",
    authToken: "",
    useDownlinkToken: true,
    deviceIdField: "hardwareId",
    responseKeyField: "lteAesKey"
  });

  await assert.rejects(
    provider.getKey("00001111"),
    /HTTP key provider is configured to use the downlink token, but no auth service was provided/
  );
});
