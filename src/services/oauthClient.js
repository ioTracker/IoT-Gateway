const DEFAULT_REFRESH_SKEW_SECONDS = 60;
const DEFAULT_RETRY_DELAY_MS = 10000;

async function fetchClientCredentialsToken(config) {
  const actualTimeoutMs = config.timeoutMs || 5000;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), actualTimeoutMs);
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: config.clientId,
    client_secret: config.clientSecret
  });

  try {
    const response = await fetch(config.tokenEndpoint, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded"
      },
      body,
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
      const responseError = new Error(
        `Token request to ${config.tokenEndpoint} failed with status ${response.status}${text ? `: ${text}` : ""}`
      );
      responseError.code = "OAUTH_TOKEN_RESPONSE_ERROR";
      responseError.statusCode = response.status;
      throw responseError;
    }

    if (!json.access_token || typeof json.access_token !== "string") {
      const tokenError = new Error(`Token response from ${config.tokenEndpoint} did not include a string access_token`);
      tokenError.code = "OAUTH_TOKEN_INVALID_RESPONSE";
      throw tokenError;
    }

    if (typeof json.expires_in !== "number" || json.expires_in <= 0) {
      const tokenError = new Error(`Token response from ${config.tokenEndpoint} did not include a positive numeric expires_in`);
      tokenError.code = "OAUTH_TOKEN_INVALID_RESPONSE";
      throw tokenError;
    }

    return {
      accessToken: json.access_token,
      tokenType: typeof json.token_type === "string" ? json.token_type : "Bearer",
      expiresIn: json.expires_in
    };
  } catch (error) {
    if (controller.signal.aborted) {
      const timeoutError = new Error(`Token request to ${config.tokenEndpoint} timed out after ${actualTimeoutMs}ms`);
      timeoutError.code = "OAUTH_TOKEN_REQUEST_TIMEOUT";
      timeoutError.cause = error;
      throw timeoutError;
    }

    if (
      error instanceof Error &&
      !error.code &&
      !error.message.startsWith(`Token request to ${config.tokenEndpoint}`)
    ) {
      const requestError = new Error(`Token request to ${config.tokenEndpoint} failed: ${error.message}`);
      requestError.code = "OAUTH_TOKEN_REQUEST_FAILED";
      requestError.cause = error;
      throw requestError;
    }

    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

class OAuthClientCredentialsService {
  constructor(config, { logger } = {}) {
    this.config = {
      refreshSkewSeconds: DEFAULT_REFRESH_SKEW_SECONDS,
      retryDelayMs: DEFAULT_RETRY_DELAY_MS,
      ...config
    };
    this.logger = logger;
    this.currentToken = null;
    this.refreshTimer = null;
    this.refreshPromise = null;
    this.stopped = false;
  }

  async start() {
    this.stopped = false;
    const token = await this.refresh();
    this.logger?.info("Downlink API access token loaded", {
      tokenType: token.tokenType,
      expiresIn: token.expiresIn
    });
    return token;
  }

  stop() {
    this.stopped = true;
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
  }

  async getAccessToken() {
    if (!this.currentToken || this.isExpired(this.currentToken)) {
      await this.refresh();
    } else if (this.shouldRefresh(this.currentToken)) {
      this.refresh().catch((error) => {
        this.logger?.warn("Downlink API access token refresh failed", {
          error: error.message
        });
        this.scheduleRetry();
      });
    }

    return this.currentToken.accessToken;
  }

  async refresh() {
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    this.refreshPromise = this.loadToken()
      .finally(() => {
        this.refreshPromise = null;
      });

    return this.refreshPromise;
  }

  async loadToken() {
    const token = await fetchClientCredentialsToken(this.config);
    const tokenWithTimes = this.withRefreshTimes(token);
    this.currentToken = tokenWithTimes;
    this.scheduleRefresh(tokenWithTimes);
    return tokenWithTimes;
  }

  withRefreshTimes(token) {
    const issuedAtMs = Date.now();
    const expiresAtMs = token.expiresIn === null
      ? null
      : issuedAtMs + token.expiresIn * 1000;
    const refreshAtMs = expiresAtMs === null
      ? null
      : expiresAtMs - this.getRefreshSkewMs(token.expiresIn);

    return {
      ...token,
      issuedAtMs,
      expiresAtMs,
      refreshAtMs
    };
  }

  getRefreshSkewMs(expiresIn) {
    const configuredSkewMs = this.config.refreshSkewSeconds * 1000;
    const halfLifetimeMs = Math.floor((expiresIn * 1000) / 2);
    return Math.min(configuredSkewMs, halfLifetimeMs);
  }

  shouldRefresh(token) {
    if (!token.refreshAtMs) {
      return false;
    }

    return Date.now() >= token.refreshAtMs;
  }

  isExpired(token) {
    if (!token.expiresAtMs) {
      return false;
    }

    return Date.now() >= token.expiresAtMs;
  }

  scheduleRefresh(token) {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }

    if (this.stopped || !token.refreshAtMs) {
      return;
    }

    const delayMs = Math.max(token.refreshAtMs - Date.now(), 0);
    this.refreshTimer = setTimeout(() => {
      this.refreshTimer = null;
      this.refresh().catch((error) => {
        this.logger?.warn("Downlink API access token refresh failed", {
          error: error.message
        });
        this.scheduleRetry();
      });
    }, delayMs);

    if (typeof this.refreshTimer.unref === "function") {
      this.refreshTimer.unref();
    }
  }

  scheduleRetry() {
    if (this.stopped || this.refreshTimer) {
      return;
    }

    this.refreshTimer = setTimeout(() => {
      this.refreshTimer = null;
      this.refresh().catch((error) => {
        this.logger?.warn("Downlink API access token refresh retry failed", {
          error: error.message
        });
        this.scheduleRetry();
      });
    }, this.config.retryDelayMs);

    if (typeof this.refreshTimer.unref === "function") {
      this.refreshTimer.unref();
    }
  }
}

module.exports = {
  fetchClientCredentialsToken,
  OAuthClientCredentialsService
};
