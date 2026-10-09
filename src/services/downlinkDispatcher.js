const { buildRetryInfoString, formatRetryEvent } = require("../retryInfo");
const { serializeError } = require("../httpClient");

class DownlinkDispatcher {
  constructor({ logger, parser, includeCrypto = false, includeRetryInfo = false }) {
    this.logger = logger;
    this.parser = parser;
    this.includeCrypto = includeCrypto;
    this.includeRetryInfo = includeRetryInfo;
  }

  prepare(downlinkRequest) {
    const formatter = this.parser.formatEncryptedDownlinkMessage || this.parser.formatDownlinkMessage;
    const payload = formatter(downlinkRequest);
    const downlink = downlinkRequest.downlinks?.[0] || null;
    const crypto = this.includeCrypto ? this.buildCryptoDebug(downlinkRequest, payload) : null;

    return {
      payload,
      downlink,
      downlinkRequest,
      crypto
    };
  }

  buildCryptoDebug(downlinkRequest, payload) {
    if (!downlinkRequest.encryption || !this.parser.parseTlvPayload || !this.parser.getTlvAdditionalAuthenticatedData) {
      return null;
    }

    const parsedPayload = this.parser.parseTlvPayload(payload, { direction: "downlink" });
    if (!Object.prototype.hasOwnProperty.call(parsedPayload, "encryptedMessage")) {
      return null;
    }

    const input = this.parser.formatDownlinkMessage({
      uplinkAck: downlinkRequest.uplinkAck,
      fCntDown: downlinkRequest.fCntDown,
      downlinks: downlinkRequest.downlinks
    });
    const aad = this.parser.getTlvAdditionalAuthenticatedData(parsedPayload);

    return {
      input: input.toString("hex").toUpperCase(),
      aad: aad ? aad.toString("hex").toUpperCase() : null,
      iv: parsedPayload.iv ? Buffer.from(parsedPayload.iv).toString("hex").toUpperCase() : null,
      ciphertext: parsedPayload.encryptedMessage
        ? Buffer.from(parsedPayload.encryptedMessage).toString("hex").toUpperCase()
        : null
    };
  }

  async sendPrepared(context, preparedDownlink, options = {}) {
    try {
      const { payload, downlink, downlinkRequest, crypto } = preparedDownlink;
      await context.sendDownlink(payload, downlink);
      if (this.includeCrypto && crypto) {
        this.logger.debug?.("Downlink crypto parameters", {
          deviceId: context.deviceId,
          transport: context.transport,
          crypto
        });
      }
      if (this.includeRetryInfo) {
        this.logger.info("Retry info", {
          deviceId: context.deviceId,
          transport: context.transport,
          event: formatRetryEvent("downlink_tx"),
          retry: buildRetryInfoString(downlinkRequest, {
            retransmitCount: options.retryAttempt ?? downlinkRequest.retransmitCount ?? 0
          })
        });
      }
      this.logger.info("Downlink sent", {
        deviceId: context.deviceId,
        transport: context.transport,
        downlinkRequest,
        downlink,
        downlinkHex: payload.toString("hex").toUpperCase(),
        isRetry: Boolean(options.isRetry),
        ...(options.retryAttempt === null || options.retryAttempt === undefined
          ? {}
          : { retryAttempt: options.retryAttempt })
      });
    } catch (error) {
      this.logger.error("Failed to send downlink", {
        deviceId: context.deviceId,
        transport: context.transport,
        error: error.message,
        errorDetails: serializeError(error)
      });
      throw error;
    }
  }

  async schedule(context, downlinkRequest, options = {}) {
    const preparedDownlink = this.prepare(downlinkRequest);
    await this.sendPrepared(context, preparedDownlink, options);
    return preparedDownlink;
  }
}

module.exports = {
  DownlinkDispatcher
};
