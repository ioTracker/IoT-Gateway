const crypto = require("crypto");
const parser = require("./parser");
const { serializeError } = require("./httpClient");
const { buildRetryInfoString, formatRetryEvent } = require("./retryInfo");

function encodeRawPayloadAsHex(rawPayload) {
  if (Buffer.isBuffer(rawPayload)) {
    return rawPayload.toString("hex").toUpperCase();
  }

  if (rawPayload instanceof Uint8Array) {
    return Buffer.from(rawPayload.buffer, rawPayload.byteOffset, rawPayload.byteLength)
      .toString("hex")
      .toUpperCase();
  }

  if (rawPayload instanceof ArrayBuffer) {
    return Buffer.from(rawPayload).toString("hex").toUpperCase();
  }

  if (typeof rawPayload === "string") {
    const trimmed = rawPayload.trim();
    if (parser.isHexString(trimmed)) {
      return trimmed.toUpperCase();
    }
    return Buffer.from(rawPayload, "utf8").toString("hex").toUpperCase();
  }

  return Buffer.from(String(rawPayload), "utf8").toString("hex").toUpperCase();
}

function serializeForDebug(value) {
  if (Buffer.isBuffer(value)) {
    return value.toString("hex").toUpperCase();
  }

  if (Array.isArray(value)) {
    return value.map((entry) => serializeForDebug(entry));
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, serializeForDebug(entry)])
    );
  }

  return value;
}

function normalizeKeyForDebug(key) {
  if (key === null || key === undefined) {
    return null;
  }

  const keyBuffer = Buffer.isBuffer(key) ? key : Buffer.from(key.trim(), "hex");

  return {
    format: Buffer.isBuffer(key) ? "buffer" : "hex",
    hex: keyBuffer.toString("hex").toUpperCase(),
    sha256: crypto.createHash("sha256").update(keyBuffer).digest("hex").toUpperCase()
  };
}

function getIvDebug(message, receivedAt) {
  if (!message.iv) {
    return null;
  }

  const ivBuffer = Buffer.from(message.iv);
  const debug = {
    value: serializeForDebug(ivBuffer)
  };

  if (ivBuffer.length === 12 && !Object.prototype.hasOwnProperty.call(message, "unsyncedClock")) {
    const timestampSeconds = ivBuffer.readUInt32BE(8);
    const currentTimestampSeconds = Math.floor(receivedAt / 1000);
    debug.timestampSeconds = timestampSeconds;
    debug.timestampIso = new Date(timestampSeconds * 1000).toISOString();
    debug.clockSkewSeconds = Math.abs(currentTimestampSeconds - timestampSeconds);
  }

  return debug;
}

function buildAdditionalAuthenticatedDataDebug(message) {
  const additionalAuthenticatedData = parser.getTlvAdditionalAuthenticatedData(message);
  if (!additionalAuthenticatedData) {
    return null;
  }

  return additionalAuthenticatedData.toString("hex").toUpperCase();
}

function buildTlvDebugBlocks(rawPayload, decryptedPlaintext) {
  const blocks = parser.getTlvBlocks(rawPayload, { direction: "uplink" });
  const encryptedMessage = blocks.find((block) => block.tagName === "encryptedMessage");

  if (encryptedMessage && decryptedPlaintext !== null) {
    encryptedMessage.contents = parser.getTlvBlocks(
      Buffer.from(decryptedPlaintext, "hex"),
      { direction: "uplink" }
    );
  }

  return blocks;
}

function buildUplinkCryptoDebug(message, key, receivedAt, config) {
  const encryptedMessage = message.encryptedMessage ? Buffer.from(message.encryptedMessage) : null;
  const signature = message.signature ? Buffer.from(message.signature) : null;

  return {
    encrypted: hasEncryptedData(message),
    algorithm: config.payload?.encryptionAlgorithm,
    allowedClockSkewSeconds: config.payload?.allowedClockSkewSeconds,
    cryptoMode: message.cryptoMode,
    unsyncedClock: Object.prototype.hasOwnProperty.call(message, "unsyncedClock")
      ? message.unsyncedClock
      : false,
    plaintextFields: serializeForDebug(getPlaintextPayloadPart(message)),
    iv: getIvDebug(message, receivedAt),
    encryptedMessage: encryptedMessage ? serializeForDebug(encryptedMessage) : null,
    signature: signature ? serializeForDebug(signature) : null,
    additionalAuthenticatedData: buildAdditionalAuthenticatedDataDebug(message),
    key: {
      required: hasEncryptedData(message),
      provider: config.keyProvider?.type,
      loaded: Boolean(key),
      material: normalizeKeyForDebug(key)
    }
  };
}

function getPlaintextPayloadPart(message) {
  const plaintextFields = { ...message };
  delete plaintextFields.encryptedMessage;
  delete plaintextFields.signature;
  return plaintextFields;
}

function hasEncryptedData(message) {
  return Object.prototype.hasOwnProperty.call(message, "encryptedMessage");
}

function getRetransmitKey(deviceId, fCntDown) {
  return `${deviceId}:${fCntDown}`;
}

function getNonNegativeInteger(value, defaultValue = 0) {
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) || parsed < 0 ? defaultValue : parsed;
}

class UplinkHandler {
  constructor({ config, keyProvider, forwarder, downlinkService, downlinkDispatcher, logger }) {
    this.config = config;
    this.keyProvider = keyProvider;
    this.forwarder = forwarder;
    this.downlinkService = downlinkService;
    this.downlinkDispatcher = downlinkDispatcher;
    this.logger = logger;
    this.pendingRetransmits = new Map();
    this.pendingDownlinksByDevice = new Map();
  }

  forwardAsync(outbound) {
    try {
      const forwardPromise = this.forwarder.forward(outbound);
      void Promise.resolve(forwardPromise).catch((error) => {
        this.logger.error("Uplink forwarding failed", {
          error: error.message,
          code: error.code,
          errorDetails: serializeError(error),
          deviceId: outbound.deviceId,
          transport: outbound.transport
        });
      });
    } catch (error) {
      this.logger.error("Uplink forwarding failed", {
        error: error.message,
        code: error.code,
        errorDetails: serializeError(error),
        deviceId: outbound.deviceId,
        transport: outbound.transport
      });
    }
  }

  getRetransmitConfig() {
    return {
      windowMs: getNonNegativeInteger(this.config.downlink?.retransmitWindowMs, 0),
      maxRetries: getNonNegativeInteger(this.config.downlink?.retransmitMaxRetries, 0),
      reconcileIntervalMs: getNonNegativeInteger(this.config.downlink?.retransmitReconcileIntervalMs, 60000)
    };
  }

  acknowledgeDownlink(deviceId, fCntDown) {
    const key = getRetransmitKey(deviceId, fCntDown);
    const state = this.pendingRetransmits.get(key);
    if (!state) {
      return;
    }

    clearTimeout(state.timer);
    this.pendingRetransmits.delete(key);
    this.logger.info("Downlink acknowledged", {
      deviceId,
      fCntDown,
      retries: state.retriesSent
    });
  }

  cancelRetransmit(deviceId, fCntDown, reason) {
    const key = getRetransmitKey(deviceId, fCntDown);
    const state = this.pendingRetransmits.get(key);
    if (!state) {
      return;
    }

    clearTimeout(state.timer);
    this.pendingRetransmits.delete(key);
    this.logger.info("Downlink retransmit cancelled by backend", {
      deviceId,
      fCntDown,
      downlinkId: state.downlinkId,
      retries: state.retriesSent,
      ...(reason ? { reason } : {})
    });
  }

  setPendingDownlinks(deviceId, downlinks) {
    if (!Array.isArray(downlinks)) {
      return;
    }

    if (downlinks.length === 0) {
      this.pendingDownlinksByDevice.delete(deviceId);
      return;
    }

    this.pendingDownlinksByDevice.set(deviceId, [...downlinks]);
  }

  removeAcknowledgedPendingDownlink(deviceId, downlinkAck) {
    if (downlinkAck === null || downlinkAck === undefined) {
      return;
    }

    const pendingDownlinks = this.pendingDownlinksByDevice.get(deviceId);
    if (!pendingDownlinks || pendingDownlinks.length === 0) {
      return;
    }

    this.setPendingDownlinks(
      deviceId,
      pendingDownlinks.filter((downlink) => downlink.counter !== downlinkAck)
    );
  }

  shiftPendingDownlink(deviceId) {
    const pendingDownlinks = this.pendingDownlinksByDevice.get(deviceId);
    if (!pendingDownlinks || pendingDownlinks.length === 0) {
      return null;
    }

    const pendingDownlink = pendingDownlinks.shift();
    if (pendingDownlinks.length === 0) {
      this.pendingDownlinksByDevice.delete(deviceId);
    }

    return pendingDownlink;
  }

  runDownlinkUpdateAsync(action, updatePromise) {
    void Promise.resolve(updatePromise)
      .then((downlinks) => {
        if (Array.isArray(downlinks)) {
          const updatedDownlinks = action.excludeCounters
            ? downlinks.filter((downlink) => !action.excludeCounters.has(downlink.counter))
            : downlinks;
          this.setPendingDownlinks(action.deviceId, updatedDownlinks);
        }
      })
      .catch((error) => {
        this.logger.error("Downlink update failed", {
          action: action.name,
          deviceId: action.deviceId,
          error: error.message,
          code: error.code,
          errorDetails: serializeError(error)
        });
      });
  }

  runDownlinkActionAsync(action, actionPromise) {
    void Promise.resolve(actionPromise)
      .catch((error) => {
        this.logger.error("Downlink update failed", {
          action: action.name,
          deviceId: action.deviceId,
          error: error.message,
          code: error.code,
          errorDetails: serializeError(error)
        });
      });
  }

  scheduleRetransmit(context, preparedDownlink, pendingDownlink = null) {
    if (context.supportsRetransmit === false) {
      return;
    }

    const fCntDown = preparedDownlink.downlinkRequest.fCntDown;
    if (fCntDown === null || fCntDown === undefined) {
      return;
    }

    const { windowMs, maxRetries, reconcileIntervalMs } = this.getRetransmitConfig();
    if (windowMs <= 0 || maxRetries <= 0) {
      return;
    }

    const key = getRetransmitKey(context.deviceId, fCntDown);
    const existingState = this.pendingRetransmits.get(key);
    if (existingState) {
      clearTimeout(existingState.timer);
    }

    const state = {
      context,
      preparedDownlink,
      downlinkId: pendingDownlink?.id ?? null,
      fCntDown,
      retriesSent: 0,
      initialSentAt: new Date().toISOString(),
      lastSentAt: new Date().toISOString(),
      lastReconciledAt: Date.now(),
      timer: null
    };

    const reconcileIfDue = async () => {
      if (
        reconcileIntervalMs <= 0 ||
        Date.now() - state.lastReconciledAt < reconcileIntervalMs
      ) {
        return false;
      }

      state.lastReconciledAt = Date.now();
      const [decision] = await this.downlinkService.reconcileRetransmits(context.deviceId, [{
        id: state.downlinkId,
        counter: fCntDown,
        retriesSent: state.retriesSent,
        initialSentAt: state.initialSentAt,
        lastSentAt: state.lastSentAt
      }]);

      if (decision?.action === "cancel") {
        this.cancelRetransmit(context.deviceId, fCntDown, decision.reason);
        return true;
      }

      return false;
    };

    const scheduleNextAttempt = () => {
      state.timer = setTimeout(() => {
        if (!this.pendingRetransmits.has(key)) {
          return;
        }

        if (state.retriesSent >= maxRetries) {
          this.pendingRetransmits.delete(key);
          this.logger.warn?.("Downlink retransmit limit reached", {
            deviceId: context.deviceId,
            fCntDown,
            retries: state.retriesSent
          });
          return;
        }

        void (async () => {
          try {
            const cancelled = await reconcileIfDue();
            if (cancelled || this.pendingRetransmits.get(key) !== state) {
              return;
            }
          } catch (error) {
            this.logger.error("Downlink retransmit reconciliation failed", {
              deviceId: context.deviceId,
              fCntDown,
              error: error.message,
              code: error.code,
              errorDetails: serializeError(error)
            });
          }

          state.retriesSent += 1;
          try {
            await this.downlinkDispatcher.sendPrepared(context, preparedDownlink, {
              isRetry: true,
              retryAttempt: state.retriesSent
            });
            state.lastSentAt = new Date().toISOString();
          } catch {
            // The dispatcher logs failed sends; the next timer remains responsible for retrying.
          } finally {
            if (this.pendingRetransmits.get(key) === state) {
              scheduleNextAttempt();
            }
          }
        })();
      }, windowMs);
      state.timer.unref?.();
    };

    this.pendingRetransmits.set(key, state);
    scheduleNextAttempt();
  }

  async handle(rawPayload, context) {
    const receivedAt = context.receivedAt || Date.now();
    this.logger.debug?.("Uplink received", {
      transport: context.transport,
      rawPayload: encodeRawPayloadAsHex(rawPayload)
    });

    const message = parser.parseTlvUplinkMessage(rawPayload);
    const deviceId = parser.getTlvDeviceId(message);
    const requiresDecryption = hasEncryptedData(message);
    const key = requiresDecryption
      ? await this.keyProvider.getKey(deviceId, parser.buildTlvMetadata(message))
      : null;

    if (this.config.logging?.includeCrypto && requiresDecryption) {
      this.logger.debug?.("Uplink crypto parameters", {
        deviceId,
        transport: context.transport,
        crypto: buildUplinkCryptoDebug(message, key, receivedAt, this.config)
      });
    }

    const decrypted = parser.decryptTlvUplinkMessage(message, key, {
      algorithm: this.config.payload.encryptionAlgorithm,
      allowedClockSkewSeconds: this.config.payload.allowedClockSkewSeconds
    });
    const metadata = parser.buildTlvMetadata(decrypted.payload);

    const outbound = {
      deviceId,
      payload: encodeRawPayloadAsHex(rawPayload),
      uplink: decrypted.payload,
      receivedAt: new Date(receivedAt).toISOString(),
      transport: context.transport
    };

    this.logger.info("Uplink decrypted", {
      deviceId,
      transport: context.transport,
      uplink: outbound.uplink
    });
    if (this.config.logging?.includeRetryInfo) {
      this.logger.info("Retry info", {
        deviceId,
        transport: context.transport,
        event: formatRetryEvent("uplink_rx"),
        retry: buildRetryInfoString(decrypted.payload)
      });
    }

    this.forwardAsync(outbound);
    const canSendDownlink = decrypted.payload.isConfirmed === true;
    const hasDownlinkAck = Object.prototype.hasOwnProperty.call(decrypted.payload, "downlinkAck");
    let downlinkUpdateAction = null;
    if (hasDownlinkAck) {
      this.acknowledgeDownlink(deviceId, decrypted.payload.downlinkAck);
      this.removeAcknowledgedPendingDownlink(deviceId, decrypted.payload.downlinkAck);
      downlinkUpdateAction = {
        name: "confirm-pending-downlink",
        deviceId,
        excludeCounters: new Set([decrypted.payload.downlinkAck])
      };
      this.runDownlinkUpdateAsync(
        downlinkUpdateAction,
        this.downlinkService.confirmAcknowledgedDownlink(deviceId, decrypted.payload.downlinkAck)
      );
    }

    let pendingDownlink = null;
    if (canSendDownlink) {
      pendingDownlink = this.shiftPendingDownlink(deviceId);
      if (!pendingDownlink && !hasDownlinkAck) {
        this.setPendingDownlinks(deviceId, await this.downlinkService.getPendingDownlinks(deviceId, metadata));
        pendingDownlink = this.shiftPendingDownlink(deviceId);
      }
    }

    const downlinkContext = {
      ...context,
      deviceId
    };
    const hasUplinkAck = canSendDownlink && Object.prototype.hasOwnProperty.call(decrypted.payload, "fCntUp");
    if (hasUplinkAck || pendingDownlink) {
      if (pendingDownlink?.counter !== null && pendingDownlink?.counter !== undefined) {
        downlinkUpdateAction?.excludeCounters.add(pendingDownlink.counter);
      }
      const preparedDownlink = await this.downlinkDispatcher.schedule(downlinkContext, {
        ...(hasUplinkAck
          ? { uplinkAck: decrypted.payload.fCntUp }
          : {}),
        ...(!pendingDownlink || pendingDownlink.counter === null || pendingDownlink.counter === undefined
          ? {}
          : { fCntDown: pendingDownlink.counter }),
        ...(pendingDownlink
          ? { downlinks: [pendingDownlink.payload] }
          : {}),
        ...(requiresDecryption
          ? {
              encryption: {
                key,
                algorithm: this.config.payload.encryptionAlgorithm,
                version: decrypted.payload.version,
                stid: decrypted.payload.stid
              }
            }
          : {})
      });
      if (preparedDownlink) {
        this.scheduleRetransmit(downlinkContext, preparedDownlink, pendingDownlink);
      }
      if (pendingDownlink) {
        this.runDownlinkActionAsync({
          name: "mark-downlink-sent",
          deviceId
        }, this.downlinkService.markDownlinkSent(deviceId, pendingDownlink.id));
      }
    }

    return {
      deviceId,
      metadata,
      decrypted,
      pendingChange: Boolean(pendingDownlink)
    };
  }

  async debug(rawPayload, context) {
    const receivedAt = context.receivedAt || Date.now();
    const rawPayloadHex = encodeRawPayloadAsHex(rawPayload);
    const message = parser.parseTlvUplinkMessage(rawPayload);
    const deviceId = parser.getTlvDeviceId(message);
    const hasEncryptedMessageField = Object.prototype.hasOwnProperty.call(message, "encryptedMessage");
    const requiresDecryption = hasEncryptedData(message);
    const plaintextPayloadPart = getPlaintextPayloadPart(message);
    let key = null;
    let decrypted = {
      payload: plaintextPayloadPart,
      plaintext: null
    };
    let encryptionFailure = null;

    if (hasEncryptedMessageField && !requiresDecryption) {
      encryptionFailure = {
        message: "Encrypted payload may not be empty",
        code: undefined
      };
    } else if (requiresDecryption) {
      try {
        key = await this.keyProvider.getKey(deviceId, parser.buildTlvMetadata(message));
        decrypted = parser.decryptTlvUplinkMessage(message, key, {
          algorithm: this.config.payload.encryptionAlgorithm,
          allowedClockSkewSeconds: this.config.payload.allowedClockSkewSeconds
        });
      } catch (error) {
        encryptionFailure = {
          message: error.message,
          code: error.code
        };
      }
    }

    const metadata = parser.buildTlvMetadata(decrypted.payload);
    const encryptedMessage = message.encryptedMessage ? Buffer.from(message.encryptedMessage) : null;
    const signature = message.signature ? Buffer.from(message.signature) : null;

    return {
      deviceId,
      receivedAt: new Date(receivedAt).toISOString(),
      transport: context.transport,
      rawPayload: {
        bytes: rawPayloadHex.length / 2,
        hex: rawPayloadHex
      },
      tlv: buildTlvDebugBlocks(rawPayload, decrypted.plaintext),
      parsedPayload: serializeForDebug(decrypted.payload),
      metadata,
      debug: {
        initialParsedPayload: serializeForDebug(message),
        encryption: {
          encrypted: hasEncryptedMessageField,
          decrypted: hasEncryptedMessageField ? !encryptionFailure : false,
          failure: encryptionFailure,
          algorithm: this.config.payload.encryptionAlgorithm,
          allowedClockSkewSeconds: this.config.payload.allowedClockSkewSeconds,
          cryptoMode: message.cryptoMode,
          unsyncedClock: Object.prototype.hasOwnProperty.call(message, "unsyncedClock")
            ? message.unsyncedClock
            : false,
          iv: getIvDebug(message, receivedAt),
          encryptedMessage: encryptedMessage ? serializeForDebug(encryptedMessage) : null,
          signature: signature ? serializeForDebug(signature) : null,
          additionalAuthenticatedData: buildAdditionalAuthenticatedDataDebug(message),
          decryptedPlaintext: decrypted.plaintext
        },
        key: {
          required: requiresDecryption,
          provider: this.config.keyProvider?.type,
          loaded: Boolean(key),
          material: normalizeKeyForDebug(key)
        }
      }
    };
  }
}

module.exports = {
  UplinkHandler
};
