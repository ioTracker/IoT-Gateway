const test = require("node:test");
const assert = require("node:assert/strict");

const { validateConfig, getConfigWarnings } = require("../src/config");

function baseConfig(overrides = {}) {
  return {
    env: "development",
    logging: {
      includePayloads: false,
      includeCrypto: false
    },
    transport: {
      http: { enabled: true },
      udp: { enabled: false }
    },
    forward: {
      url: ""
    },
    payload: {
      encryptionAlgorithm: "aes-256-gcm",
      allowedClockSkewSeconds: 60
    },
    keyProvider: {
      type: "HTTP",
      http: { url: "https://example.test/key" },
      db: { connectionString: "" }
    },
    downlink: {
      enabled: false,
      apiUrl: ""
    },
    ...overrides
  };
}

test("validateConfig allows missing FORWARD_URL outside production", () => {
  assert.doesNotThrow(() => validateConfig(baseConfig()));
});

test("validateConfig requires FORWARD_URL in production", () => {
  assert.throws(
    () => validateConfig(baseConfig({ env: "production" })),
    /FORWARD_URL is required when NODE_ENV=production/
  );
});

test("validateConfig requires DOWNLINK_API_URL when downlink checks are enabled", () => {
  assert.throws(
    () => validateConfig(baseConfig({
      downlink: {
        enabled: true,
        apiUrl: "",
        tokenEndpoint: "https://example.test/oauth/token",
        clientId: "lte-server",
        clientSecret: "secret"
      }
    })),
    /DOWNLINK_API_URL is required when DOWNLINK_CHECK_ENABLED=true/
  );
});

test("validateConfig requires downlink OAuth credentials when downlink checks are enabled", () => {
  assert.throws(
    () => validateConfig(baseConfig({
      downlink: {
        enabled: true,
        apiUrl: "https://example.test/lte-connector",
        tokenEndpoint: "",
        clientId: "",
        clientSecret: ""
      }
    })),
    /DOWNLINK_TOKEN_ENDPOINT, DOWNLINK_CLIENT_ID, and DOWNLINK_CLIENT_SECRET are required when DOWNLINK_CHECK_ENABLED=true/
  );
});

test("validateConfig requires downlink OAuth credentials when HTTP key provider reuses downlink token", () => {
  assert.throws(
    () => validateConfig(baseConfig({
      keyProvider: {
        type: "HTTP",
        http: {
          url: "https://example.test/key",
          useDownlinkToken: true
        },
        db: { connectionString: "" }
      },
      downlink: {
        enabled: false,
        apiUrl: "",
        tokenEndpoint: "",
        clientId: "",
        clientSecret: ""
      }
    })),
    /DOWNLINK_TOKEN_ENDPOINT, DOWNLINK_CLIENT_ID, and DOWNLINK_CLIENT_SECRET are required when KEY_HTTP_USE_DOWNLINK_TOKEN=true/
  );
});

test("validateConfig requires complete downlink OAuth credentials when partially configured", () => {
  assert.throws(
    () => validateConfig(baseConfig({
      downlink: {
        enabled: false,
        apiUrl: "",
        tokenEndpoint: "https://example.test/oauth/token",
        clientId: "lte-server",
        clientSecret: ""
      }
    })),
    /DOWNLINK_TOKEN_ENDPOINT, DOWNLINK_CLIENT_ID, and DOWNLINK_CLIENT_SECRET must be configured together/
  );
});

test("validateConfig allows complete downlink OAuth credentials", () => {
  assert.doesNotThrow(() => validateConfig(baseConfig({
    downlink: {
      enabled: true,
      apiUrl: "https://example.test/lte-connector",
      tokenEndpoint: "https://example.test/oauth/token",
      clientId: "lte-server",
      clientSecret: "secret"
    }
  })));
});

test("getConfigWarnings returns no warnings for the default safe configuration", () => {
  assert.deepEqual(getConfigWarnings(baseConfig()), []);
});

test("getConfigWarnings warns when allowed encryption clock skew is changed", () => {
  const warnings = getConfigWarnings(baseConfig({
    payload: {
      encryptionAlgorithm: "aes-256-gcm",
      allowedClockSkewSeconds: 300
    }
  }));

  assert.deepEqual(warnings[0], {
    setting: "ENCRYPTION_ALLOWED_CLOCK_SKEW_SECONDS",
    value: 300,
    defaultValue: 60,
    risk: "Changing the allowed clock skew changes replay protection and may reject valid messages or accept older messages"
  });
});

test("getConfigWarnings reports all configured security risks without secrets", () => {
  const warnings = getConfigWarnings(baseConfig({
    env: "production",
    logging: { includePayloads: true, includeCrypto: true },
    payload: {
      encryptionAlgorithm: "aes-128-gcm",
      allowedClockSkewSeconds: 60
    },
    forward: { url: "http://forward.example.test" },
    keyProvider: {
      type: "HTTP",
      http: {
        url: "http://keys.example.test",
        authToken: "must-not-be-logged"
      },
      db: { connectionString: "" }
    }
  }));

  assert.deepEqual(
    warnings.map(({ setting }) => setting),
    ["ENCRYPTION_ALGORITHM", "LOG_INCLUDE_PAYLOADS", "LOG_INCLUDE_CRYPTO", "FORWARD_URL", "KEY_HTTP_URL"]
  );
  assert.doesNotMatch(JSON.stringify(warnings), /must-not-be-logged/);
});
