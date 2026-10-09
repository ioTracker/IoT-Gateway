const { postJson } = require("../httpClient");

function encodeBuffersAsHex(value) {
  if (Buffer.isBuffer(value)) {
    return value.toString("hex").toUpperCase();
  }

  if (Array.isArray(value)) {
    return value.map((entry) => encodeBuffersAsHex(entry));
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, encodeBuffersAsHex(entry)])
    );
  }

  return value;
}

class Forwarder {
  constructor(config) {
    this.config = config;
  }

  async forward(message) {
    if (!this.config.url) {
      return undefined;
    }

    return postJson(this.config.url, encodeBuffersAsHex(message), {
      timeoutMs: this.config.timeoutMs,
      authHeader: this.config.authHeader,
      authToken: this.config.authToken
    });
  }
}

module.exports = {
  Forwarder,
  encodeBuffersAsHex
};
