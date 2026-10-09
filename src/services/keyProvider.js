const { postJson } = require("../httpClient");

async function loadOptionalModule(moduleName) {
  try {
    return require(moduleName);
  } catch (error) {
    throw new Error(`Module "${moduleName}" is required but not installed`);
  }
}

async function getCachedKey(cache, deviceId, loadKey) {
  if (cache.has(deviceId)) {
    return cache.get(deviceId);
  }

  const keyPromise = loadKey().catch((error) => {
    cache.delete(deviceId);
    throw error;
  });
  cache.set(deviceId, keyPromise);
  return keyPromise;
}

class HttpKeyProvider {
  constructor(config, { authService } = {}) {
    this.config = config;
    this.authService = authService;
    this.keyCache = new Map();
  }

  async buildRequestOptions() {
    const options = {
      method: this.config.method,
      timeoutMs: this.config.timeoutMs,
      authHeader: this.config.authHeader,
      authToken: this.config.authToken
    };

    if (this.config.useDownlinkToken) {
      if (!this.authService) {
        throw new Error("HTTP key provider is configured to use the downlink token, but no auth service was provided");
      }

      const accessToken = await this.authService.getAccessToken();
      options.authHeader = "Authorization";
      options.authToken = `Bearer ${accessToken}`;
    }

    return options;
  }

  async getKey(deviceId, metadata = {}) {
    return getCachedKey(this.keyCache, deviceId, () => this.fetchKey(deviceId, metadata));
  }

  async fetchKey(deviceId, metadata = {}) {
    const body = {
      [this.config.deviceIdField]: deviceId,
      metadata
    };
    const response = await postJson(this.config.url, body, await this.buildRequestOptions());
    const key = response[this.config.responseKeyField];
    if (!key) {
      throw new Error(`Key service response did not include "${this.config.responseKeyField}" (deviceId = ${deviceId})`);
    }
    return key;
  }
}

class DbKeyProvider {
  constructor(config) {
    this.config = config;
    this.pool = null;
    this.keyCache = new Map();
  }

  async getPool() {
    if (this.pool) {
      return this.pool;
    }

    if (this.config.client === "postgres") {
      const { Pool } = await loadOptionalModule("pg");
      this.pool = new Pool({ connectionString: this.config.connectionString });
      return this.pool;
    }

    if (this.config.client === "mysql") {
      const mysql = await loadOptionalModule("mysql2/promise");
      this.pool = mysql.createPool(this.config.connectionString);
      return this.pool;
    }

    if (this.config.client === "mssql") {
      const mssql = await loadOptionalModule("mssql");
      this.pool = await mssql.connect(this.config.connectionString);
      return this.pool;
    }

    throw new Error(`Unsupported DB client "${this.config.client}"`);
  }

  async getKey(deviceId) {
    return getCachedKey(this.keyCache, deviceId, () => this.queryKey(deviceId));
  }

  async queryKey(deviceId) {
    const pool = await this.getPool();
    const sql = `SELECT ${this.config.keyColumn} AS device_key FROM ${this.config.table} WHERE ${this.config.deviceIdColumn} = ?`;

    if (this.config.client === "postgres") {
      const pgSql = `SELECT ${this.config.keyColumn} AS device_key FROM ${this.config.table} WHERE ${this.config.deviceIdColumn} = $1`;
      const result = await pool.query(pgSql, [deviceId]);
      if (!result.rows[0] || !result.rows[0].device_key) {
        throw new Error(`No encryption key found for device "${deviceId}"`);
      }
      return result.rows[0].device_key;
    }

    if (this.config.client === "mysql") {
      const [rows] = await pool.query(sql, [deviceId]);
      if (!rows[0] || !rows[0].device_key) {
        throw new Error(`No encryption key found for device "${deviceId}"`);
      }
      return rows[0].device_key;
    }

    if (this.config.client === "mssql") {
      const request = pool.request();
      request.input("deviceId", deviceId);
      const result = await request.query(
        `SELECT ${this.config.keyColumn} AS device_key FROM ${this.config.table} WHERE ${this.config.deviceIdColumn} = @deviceId`
      );
      if (!result.recordset[0] || !result.recordset[0].device_key) {
        throw new Error(`No encryption key found for device "${deviceId}"`);
      }
      return result.recordset[0].device_key;
    }

    throw new Error(`Unsupported DB client "${this.config.client}"`);
  }
}

function createKeyProvider(config, { authService } = {}) {
  if (config.type === "DB") {
    return new DbKeyProvider(config.db);
  }
  return new HttpKeyProvider(config.http, { authService });
}

module.exports = {
  HttpKeyProvider,
  DbKeyProvider,
  createKeyProvider
};
