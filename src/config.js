const path = require("path");
const dotenv = require("dotenv");

const DEFAULT_ENCRYPTION_ALGORITHM = "aes-256-gcm";
const DEFAULT_ALLOWED_CLOCK_SKEW_SECONDS = 60;

dotenv.config({ path: process.env.ENV_FILE || path.resolve(process.cwd(), ".env") });

function bool(value, defaultValue = false) {
  if (value === undefined) {
    return defaultValue;
  }
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

function int(value, defaultValue) {
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? defaultValue : parsed;
}

const config = {
  env: process.env.NODE_ENV || "development",
  logging: {
    level: process.env.LOG_LEVEL || "info",
    includePayloads: bool(process.env.LOG_INCLUDE_PAYLOADS, false),
    includeCrypto: bool(process.env.LOG_INCLUDE_CRYPTO, false),
    includeRetryInfo: bool(process.env.LOG_RETRY_INFO, false)
  },
  transport: {
    http: {
      enabled: bool(process.env.HTTP_ENABLED, true),
      host: process.env.HTTP_HOST || "0.0.0.0",
      port: int(process.env.HTTP_PORT, 8080),
      uplinkPath: process.env.HTTP_UPLINK_PATH || "/uplink"
    },
    udp: {
      enabled: bool(process.env.UDP_ENABLED, true),
      host: process.env.UDP_HOST || "0.0.0.0",
      port: int(process.env.UDP_PORT, 5000),
      type: process.env.UDP_TYPE || "udp4"
    }
  },
  payload: {
    encryptionAlgorithm: process.env.ENCRYPTION_ALGORITHM || DEFAULT_ENCRYPTION_ALGORITHM,
    allowedClockSkewSeconds: int(
      process.env.ENCRYPTION_ALLOWED_CLOCK_SKEW_SECONDS,
      DEFAULT_ALLOWED_CLOCK_SKEW_SECONDS
    )
  },
  keyProvider: {
    type: (process.env.KEY_PROVIDER || "HTTP").toUpperCase(),
    http: {
      url: process.env.KEY_HTTP_URL || "",
      method: (process.env.KEY_HTTP_METHOD || "POST").toUpperCase(),
      timeoutMs: int(process.env.KEY_HTTP_TIMEOUT_MS, 5000),
      authHeader: process.env.KEY_HTTP_AUTH_HEADER || "",
      authToken: process.env.KEY_HTTP_AUTH_TOKEN || "",
      useDownlinkToken: bool(process.env.KEY_HTTP_USE_DOWNLINK_TOKEN, false),
      deviceIdField: process.env.KEY_HTTP_DEVICE_ID_FIELD || "deviceId",
      responseKeyField: process.env.KEY_HTTP_RESPONSE_KEY_FIELD || "key"
    },
    db: {
      client: process.env.KEY_DB_CLIENT || "postgres",
      connectionString: process.env.KEY_DB_CONNECTION_STRING || "",
      table: process.env.KEY_DB_TABLE || "device_keys",
      deviceIdColumn: process.env.KEY_DB_DEVICE_ID_COLUMN || "device_id",
      keyColumn: process.env.KEY_DB_KEY_COLUMN || "encryption_key"
    }
  },
  forward: {
    url: process.env.FORWARD_URL || "",
    timeoutMs: int(process.env.FORWARD_TIMEOUT_MS, 5000),
    authHeader: process.env.FORWARD_AUTH_HEADER || "",
    authToken: process.env.FORWARD_AUTH_TOKEN || ""
  },
  downlink: {
    enabled: bool(process.env.DOWNLINK_CHECK_ENABLED, bool(process.env.CONFIG_CHECK_ENABLED, false)),
    apiUrl: process.env.DOWNLINK_API_URL || "",
    timeoutMs: int(process.env.DOWNLINK_CHECK_TIMEOUT_MS, int(process.env.CONFIG_CHECK_TIMEOUT_MS, 5000)),
    tokenEndpoint: process.env.DOWNLINK_TOKEN_ENDPOINT || "",
    clientId: process.env.DOWNLINK_CLIENT_ID || "",
    clientSecret: process.env.DOWNLINK_CLIENT_SECRET || "",
    idField: process.env.DOWNLINK_UUID_FIELD || "id",
    itemPayloadField: process.env.DOWNLINK_ITEM_PAYLOAD_FIELD || "payload",
    counterField: process.env.DOWNLINK_COUNTER_FIELD || "counter",
    createdAtField: process.env.DOWNLINK_CREATED_AT_FIELD || "createdAt",
    retransmitWindowMs: int(process.env.DOWNLINK_RETRANSMIT_WINDOW_MS, 0),
    retransmitMaxRetries: int(process.env.DOWNLINK_RETRANSMIT_MAX_RETRIES, 0),
    retransmitReconcileIntervalMs: int(process.env.DOWNLINK_RETRANSMIT_RECONCILE_INTERVAL_MS, 60000)
  }
};

function validateConfig(currentConfig) {
  if (!currentConfig.transport.http.enabled && !currentConfig.transport.udp.enabled) {
    throw new Error("At least one transport must be enabled");
  }
  if (currentConfig.env === "production" && !currentConfig.forward.url) {
    throw new Error("FORWARD_URL is required when NODE_ENV=production");
  }
  if (currentConfig.keyProvider.type === "HTTP" && !currentConfig.keyProvider.http.url) {
    throw new Error("KEY_HTTP_URL is required when KEY_PROVIDER=HTTP");
  }
  if (currentConfig.keyProvider.type === "DB" && !currentConfig.keyProvider.db.connectionString) {
    throw new Error("KEY_DB_CONNECTION_STRING is required when KEY_PROVIDER=DB");
  }
  if (currentConfig.downlink.enabled && !currentConfig.downlink.apiUrl) {
    throw new Error("DOWNLINK_API_URL is required when DOWNLINK_CHECK_ENABLED=true");
  }
  const downlinkOAuthValues = [
    currentConfig.downlink.tokenEndpoint,
    currentConfig.downlink.clientId,
    currentConfig.downlink.clientSecret
  ];
  if (
    currentConfig.keyProvider.type === "HTTP" &&
    currentConfig.keyProvider.http.useDownlinkToken &&
    !downlinkOAuthValues.every(Boolean)
  ) {
    throw new Error("DOWNLINK_TOKEN_ENDPOINT, DOWNLINK_CLIENT_ID, and DOWNLINK_CLIENT_SECRET are required when KEY_HTTP_USE_DOWNLINK_TOKEN=true");
  }
  if (currentConfig.downlink.enabled && !downlinkOAuthValues.every(Boolean)) {
    throw new Error("DOWNLINK_TOKEN_ENDPOINT, DOWNLINK_CLIENT_ID, and DOWNLINK_CLIENT_SECRET are required when DOWNLINK_CHECK_ENABLED=true");
  }
  if (downlinkOAuthValues.some(Boolean) && !downlinkOAuthValues.every(Boolean)) {
    throw new Error("DOWNLINK_TOKEN_ENDPOINT, DOWNLINK_CLIENT_ID, and DOWNLINK_CLIENT_SECRET must be configured together");
  }
}

function getConfigWarnings(currentConfig) {
  const warnings = [];

  if (currentConfig.payload?.allowedClockSkewSeconds !== DEFAULT_ALLOWED_CLOCK_SKEW_SECONDS) {
    warnings.push({
      setting: "ENCRYPTION_ALLOWED_CLOCK_SKEW_SECONDS",
      value: currentConfig.payload?.allowedClockSkewSeconds,
      defaultValue: DEFAULT_ALLOWED_CLOCK_SKEW_SECONDS,
      risk: "Changing the allowed clock skew changes replay protection and may reject valid messages or accept older messages"
    });
  }

  if (currentConfig.payload?.encryptionAlgorithm !== DEFAULT_ENCRYPTION_ALGORITHM) {
    warnings.push({
      setting: "ENCRYPTION_ALGORITHM",
      value: currentConfig.payload?.encryptionAlgorithm,
      defaultValue: DEFAULT_ENCRYPTION_ALGORITHM,
      risk: "A non-default encryption algorithm may be incompatible with devices or provide different security guarantees"
    });
  }

  if (currentConfig.logging?.includePayloads) {
    warnings.push({
      setting: "LOG_INCLUDE_PAYLOADS",
      value: true,
      defaultValue: false,
      risk: "Payload logging may write sensitive device data to logs"
    });
  }

  if (currentConfig.logging?.includeCrypto) {
    warnings.push({
      setting: "LOG_INCLUDE_CRYPTO",
      value: true,
      defaultValue: false,
      risk: "Crypto logging may write encryption keys, IVs, signatures, and ciphertext to logs"
    });
  }

  if (currentConfig.env === "production") {
    const endpoints = [
      ["FORWARD_URL", currentConfig.forward?.url],
      ["KEY_HTTP_URL", currentConfig.keyProvider?.type === "HTTP" && currentConfig.keyProvider?.http?.url],
      ["DOWNLINK_API_URL", currentConfig.downlink?.enabled && currentConfig.downlink?.apiUrl],
      ["DOWNLINK_TOKEN_ENDPOINT", currentConfig.downlink?.tokenEndpoint]
    ];

    for (const [setting, value] of endpoints) {
      if (typeof value === "string" && value.toLowerCase().startsWith("http://")) {
        warnings.push({
          setting,
          value,
          risk: "This production endpoint uses unencrypted HTTP; credentials or device data may be intercepted"
        });
      }
    }
  }

  return warnings;
}

module.exports = {
  config,
  validateConfig,
  getConfigWarnings
};
