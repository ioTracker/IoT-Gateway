const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const { HttpKeyProvider } = require("../src/services/keyProvider");
const { Forwarder } = require("../src/services/forwarder");
const { DownlinkService } = require("../src/services/downlinkService");
const { DownlinkDispatcher } = require("../src/services/downlinkDispatcher");
const parser = require("../src/parser");
const { UplinkHandler } = require("../src/uplinkHandler");

function parseDownlinkPayload(payload) {
  return parser.parseTlvPayload(payload, { direction: "downlink" });
}

function buildIv(timestamp) {
  const iv = Buffer.alloc(12);
  crypto.randomBytes(8).copy(iv, 0);
  iv.writeUInt32BE(timestamp, 8);
  return iv;
}

function buildEncryptedTlvMessage(stid, outerFields, innerFields, key) {
  const actualKey = key || crypto.randomBytes(32);
  const plaintextFields = {
    version: 1,
    stid,
    cryptoMode: 1,
    ...outerFields
  };
  plaintextFields.iv = buildIv(Math.floor(Date.now() / 1000));
  const aad = Buffer.from(
    parser.encodeTlvPayload(plaintextFields, { direction: "uplink" }),
    "hex"
  );
  const plaintext = Buffer.from(
    parser.encodeTlvPayload(innerFields, { direction: "uplink" }),
    "hex"
  );
  const cipher = crypto.createCipheriv("aes-256-gcm", actualKey, plaintextFields.iv);
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    key: actualKey.toString("hex").toUpperCase(),
    body: Buffer.from(
      parser.encodeTlvPayload({
        ...plaintextFields,
        signature: authTag,
        encryptedMessage: encrypted
      }, { direction: "uplink" }),
      "hex"
    )
  };
}

test("uplink handler forwards plain TLV uplinks without requesting a key", async () => {
  const requests = [];
  const originalFetch = global.fetch;

  global.fetch = async (url, options) => {
    const body = JSON.parse(options.body);
    requests.push({ url, method: options.method, body });

    if (url === "https://example.test/forward") {
      return new Response(JSON.stringify({ accepted: true, echoedDeviceId: body.deviceId }), { status: 200 });
    }
    if (url === "https://example.test/config/get-pending-downlinks") {
      return new Response(JSON.stringify([]), { status: 200 });
    }
    if (url === "https://example.test/key") {
      throw new Error("Key lookup should not be called for plain TLV uplinks");
    }

    throw new Error(`Unexpected url ${url}`);
  };

  try {
    const keyProvider = new HttpKeyProvider({
      url: "https://example.test/key",
      method: "POST",
      timeoutMs: 5000,
      deviceIdField: "deviceId",
      responseKeyField: "key"
    });
    const forwarder = new Forwarder({
      url: "https://example.test/forward",
      timeoutMs: 5000
    });
    const downlinkService = new DownlinkService({
      enabled: true,
      apiUrl: "https://example.test/config",
      timeoutMs: 5000
    });

    const logger = {
      info() {},
      error() {}
    };

    const downlinkDispatcher = new DownlinkDispatcher({
      logger,
      parser
    });

    const handler = new UplinkHandler({
      config: {
        payload: {
          encryptionAlgorithm: "aes-256-gcm"
        }
      },
      keyProvider,
      forwarder,
      downlinkService,
      downlinkDispatcher,
      logger
    });

    const payload = Buffer.from(
      parser.encodeTlvPayload({
        version: 1,
        isConfirmed: true,
        stid: "00001111",
        battery: 88,
        clickType: "single",
        fCntUp: 12355,
        fCntDown: 235
      }, { direction: "uplink" }),
      "hex"
    );

    const result = await handler.handle(payload, {
      transport: "udp",
      receivedAt: Date.now(),
      sendDownlink: async () => {}
    });

    assert.equal(result.deviceId, "00001111");
    assert.deepEqual(result.decrypted.payload, {
      version: 1,
      isConfirmed: true,
      stid: Buffer.from("00001111", "hex"),
      battery: 88,
      clickType: "single",
      fCntUp: 12355,
      fCntDown: 235
    });
    assert.equal(result.pendingChange, false);
    const forwardRequest = requests.find((request) => request.url === "https://example.test/forward");
    assert.equal(Object.prototype.hasOwnProperty.call(forwardRequest.body, "metadata"), false);
    assert.deepEqual(forwardRequest.body, {
      deviceId: "00001111",
      payload: payload.toString("hex").toUpperCase(),
      uplink: {
        version: 1,
        isConfirmed: true,
        stid: "00001111",
        battery: 88,
        clickType: "single",
        fCntUp: 12355,
        fCntDown: 235
      },
      receivedAt: forwardRequest.body.receivedAt,
      transport: "udp"
    });
    assert.deepEqual(
      requests.map((request) => request.url).sort(),
      [
        "https://example.test/config/get-pending-downlinks",
        "https://example.test/forward"
      ]
    );
  } finally {
    global.fetch = originalFetch;
  }
});

test("uplink handler accepts authentication-only encrypted TLV uplinks", async () => {
  const message = buildEncryptedTlvMessage(
    "00001111",
    {
      battery: 55
    },
    {}
  );
  const forwarded = [];

  const handler = new UplinkHandler({
    config: {
      payload: {
        encryptionAlgorithm: "aes-256-gcm"
      }
    },
    keyProvider: {
      async getKey() {
        return message.key;
      }
    },
    forwarder: {
      async forward(outbound) {
        forwarded.push(outbound);
      }
    },
    downlinkService: {
      async getPendingDownlinks() {
        return [];
      }
    },
    downlinkDispatcher: {
      async schedule() {
        throw new Error("Malformed uplinks should not schedule downlinks");
      }
    },
    logger: {
      info() {},
      error() {}
    }
  });

  const result = await handler.handle(message.body, {
    transport: "udp",
    receivedAt: Date.now(),
    sendDownlink: async () => {}
  });

  assert.equal(result.decrypted.plaintext, "");
  assert.equal(result.decrypted.payload.battery, 55);
  assert.equal(Object.prototype.hasOwnProperty.call(result.decrypted.payload, "encryptedMessage"), false);
  assert.equal(forwarded.length, 1);
});

test("uplink handler does not send an ACK when isConfirmed is absent", async () => {
  const payload = Buffer.from(
    parser.encodeTlvPayload({
      version: 1,
      stid: "00001111",
      battery: 88,
      clickType: "single",
      fCntUp: 12345
    }, { direction: "uplink" }),
    "hex"
  );
  let scheduled = false;

  const handler = new UplinkHandler({
    config: {
      payload: {
        encryptionAlgorithm: "aes-256-gcm"
      }
    },
    keyProvider: {
      async getKey() {
        throw new Error("Key lookup should not be called for plain TLV uplinks");
      }
    },
    forwarder: {
      async forward(outbound) {
        assert.equal(outbound.deviceId, "00001111");
        assert.equal(outbound.uplink.fCntUp, 12345);
        return { accepted: true };
      }
    },
    downlinkService: {
      async getPendingDownlinks() {
        throw new Error("Pending downlinks should not be checked without isConfirmed");
      }
    },
    downlinkDispatcher: {
      async schedule() {
        scheduled = true;
      }
    },
    logger: {
      info() {},
      error() {}
    }
  });

  const result = await handler.handle(payload, {
    transport: "udp",
    receivedAt: Date.now(),
    sendDownlink: async () => {
      throw new Error("Downlink should not be sent without isConfirmed");
    }
  });

  assert.equal(result.deviceId, "00001111");
  assert.equal(result.pendingChange, false);
  assert.equal(scheduled, false);
});

test("uplink handler does not send an ACK when isConfirmed is false", async () => {
  const payload = Buffer.from(
    parser.encodeTlvPayload({
      version: 1,
      isConfirmed: false,
      stid: "00001111",
      fCntUp: 12345
    }, { direction: "uplink" }),
    "hex"
  );
  let scheduled = false;

  const handler = new UplinkHandler({
    config: {
      payload: {
        encryptionAlgorithm: "aes-256-gcm"
      }
    },
    keyProvider: {
      async getKey() {
        throw new Error("Key lookup should not be called for plain TLV uplinks");
      }
    },
    forwarder: {
      async forward() {
        return { accepted: true };
      }
    },
    downlinkService: {
      async getPendingDownlinks() {
        throw new Error("Pending downlinks should not be checked when isConfirmed is false");
      }
    },
    downlinkDispatcher: {
      async schedule() {
        scheduled = true;
      }
    },
    logger: {
      info() {},
      error() {}
    }
  });

  const result = await handler.handle(payload, {
    transport: "udp",
    receivedAt: Date.now(),
    sendDownlink: async () => {
      throw new Error("Downlink should not be sent when isConfirmed is false");
    }
  });

  assert.equal(result.deviceId, "00001111");
  assert.equal(result.pendingChange, false);
  assert.equal(scheduled, false);
});

test("uplink handler confirms downlinkAck without scheduling a downlink when isConfirmed is absent", async () => {
  const payload = Buffer.from(
    parser.encodeTlvPayload({
      version: 1,
      stid: "00001111",
      fCntUp: 12345,
      downlinkAck: 235
    }, { direction: "uplink" }),
    "hex"
  );
  const events = [];

  const handler = new UplinkHandler({
    config: {
      payload: {
        encryptionAlgorithm: "aes-256-gcm"
      }
    },
    keyProvider: {
      async getKey() {
        throw new Error("Key lookup should not be called for plain TLV uplinks");
      }
    },
    forwarder: {
      async forward() {
        events.push("forward");
      }
    },
    downlinkService: {
      async getPendingDownlinks() {
        throw new Error("Pending downlinks should not be checked without isConfirmed");
      },
      async confirmAcknowledgedDownlink(deviceId, downlinkAck) {
        events.push(`ack:${deviceId}:${downlinkAck}`);
        return [];
      },
      async markDownlinkSent() {
        throw new Error("Unsent pending downlinks should not be marked sent");
      }
    },
    downlinkDispatcher: {
      async schedule() {
        throw new Error("Downlinks should not be scheduled without isConfirmed");
      }
    },
    logger: {
      info() {},
      error() {}
    }
  });

  const result = await handler.handle(payload, {
    transport: "udp",
    receivedAt: Date.now(),
    sendDownlink: async () => {
      throw new Error("Downlink should not be sent without isConfirmed");
    }
  });

  assert.equal(result.deviceId, "00001111");
  assert.equal(result.pendingChange, false);
  assert.deepEqual(events, ["forward", "ack:00001111:235"]);
});

test("uplink handler logs compact retry info when enabled", async () => {
  const payload = Buffer.from(
    parser.encodeTlvPayload({
      version: 1,
      isConfirmed: false,
      stid: "00001111",
      fCntUp: 12345,
      fCntDown: 235,
      downlinkAck: 234,
      retransmitCount: 3
    }, { direction: "uplink" }),
    "hex"
  );
  const logs = [];

  const handler = new UplinkHandler({
    config: {
      logging: {
        includeRetryInfo: true
      },
      payload: {
        encryptionAlgorithm: "aes-256-gcm"
      }
    },
    keyProvider: {
      async getKey() {
        throw new Error("Key lookup should not be called for plain TLV uplinks");
      }
    },
    forwarder: {
      async forward() {
        return { accepted: true };
      }
    },
    downlinkService: {
      async getPendingDownlinks() {
        throw new Error("Pending downlinks should not be checked when isConfirmed is false");
      },
      async confirmAcknowledgedDownlink() {
        return [];
      }
    },
    downlinkDispatcher: {
      async schedule() {
        throw new Error("Downlinks should not be scheduled when isConfirmed is false");
      }
    },
    logger: {
      info(message, context) {
        logs.push({ message, context });
      },
      error() {}
    }
  });

  await handler.handle(payload, {
    transport: "udp",
    receivedAt: Date.now(),
    sendDownlink: async () => {}
  });

  const retryLog = logs.find((log) => log.message === "Retry info");
  assert.deepEqual(retryLog.context, {
    deviceId: "00001111",
    transport: "udp",
    event: "uplink_rx  ",
    retry: "fCntUp=12345 fCntDown=  235 downlinkAck=  234 uplinkAck=      retransmitCount=    3"
  });
});

test("uplink handler sends pending downlinks without an uplink ACK when fCntUp is absent", async () => {
  const payload = Buffer.from(
    parser.encodeTlvPayload({
      version: 1,
      isConfirmed: true,
      stid: "00001111",
      battery: 88
    }, { direction: "uplink" }),
    "hex"
  );
  let scheduledDownlink;

  const handler = new UplinkHandler({
    config: {
      payload: {
        encryptionAlgorithm: "aes-256-gcm"
      }
    },
    keyProvider: {
      async getKey() {
        throw new Error("Key lookup should not be called for plain TLV uplinks");
      }
    },
    forwarder: {
      async forward() {
        return { accepted: true };
      }
    },
    downlinkService: {
      async getPendingDownlinks() {
        return [{
          payload: "12230000010502",
          id: null,
          counter: 235,
          createdAt: "2024-04-05T11:00:00.000Z"
        }];
      },
      async markDownlinkSent(deviceId, id) {
        assert.equal(deviceId, "00001111");
        assert.equal(id, null);
      }
    },
    downlinkDispatcher: {
      async schedule(context, downlink) {
        assert.equal(context.deviceId, "00001111");
        scheduledDownlink = downlink;
      }
    },
    logger: {
      info() {},
      error() {}
    }
  });

  const result = await handler.handle(payload, {
    transport: "udp",
    receivedAt: Date.now(),
    sendDownlink: async () => {}
  });

  assert.equal(result.pendingChange, true);
  assert.deepEqual(scheduledDownlink, {
    fCntDown: 235,
    downlinks: ["12230000010502"]
  });
});

test("uplink handler ignores mark-downlink-sent response when continuing the local queue", async () => {
  const payload = Buffer.from(
    parser.encodeTlvPayload({
      version: 1,
      isConfirmed: true,
      stid: "00001111"
    }, { direction: "uplink" }),
    "hex"
  );
  const scheduledDownlinks = [];
  let pendingChecks = 0;

  const handler = new UplinkHandler({
    config: {
      payload: {
        encryptionAlgorithm: "aes-256-gcm"
      }
    },
    keyProvider: {
      async getKey() {
        throw new Error("Key lookup should not be called for plain TLV uplinks");
      }
    },
    forwarder: {
      async forward() {}
    },
    downlinkService: {
      async getPendingDownlinks() {
        pendingChecks += 1;
        if (pendingChecks > 1) {
          throw new Error("Second downlink should come from the local queue");
        }

        return [
          {
            payload: "9988",
            id: "downlink-1",
            counter: 235,
            createdAt: "2024-04-05T11:00:00.000Z"
          },
          {
            payload: "AABB",
            id: "downlink-2",
            counter: 236,
            createdAt: "2024-04-05T12:00:00.000Z"
          }
        ];
      },
      async markDownlinkSent() {
        return [];
      }
    },
    downlinkDispatcher: {
      async schedule(context, downlink) {
        scheduledDownlinks.push(downlink.downlinks[0]);
      }
    },
    logger: {
      info() {},
      error() {}
    }
  });

  const context = {
    transport: "udp",
    receivedAt: Date.now(),
    sendDownlink: async () => {}
  };

  await handler.handle(payload, context);
  await new Promise((resolve) => setImmediate(resolve));
  await handler.handle(payload, context);

  assert.equal(pendingChecks, 1);
  assert.deepEqual(scheduledDownlinks, ["9988", "AABB"]);
});

test("uplink handler confirms downlinkAck and schedules the next pending downlink without checking config", async () => {
  const payload = Buffer.from(
    parser.encodeTlvPayload({
      version: 1,
      isConfirmed: true,
      stid: "00001111",
      fCntUp: 12345,
      downlinkAck: 235
    }, { direction: "uplink" }),
    "hex"
  );
  const events = [];

  const handler = new UplinkHandler({
    config: {
      payload: {
        encryptionAlgorithm: "aes-256-gcm"
      }
    },
    keyProvider: {
      async getKey() {
        throw new Error("Key lookup should not be called for plain TLV uplinks");
      }
    },
    forwarder: {
      async forward(outbound) {
        events.push(`forward:${outbound.deviceId}:${outbound.uplink.downlinkAck}`);
      }
    },
    downlinkService: {
      async getPendingDownlinks() {
        throw new Error("Normal pending downlink check should not be called when downlinkAck is present");
      },
      async confirmAcknowledgedDownlink(deviceId, downlinkAck) {
        events.push(`ack:${deviceId}:${downlinkAck}`);
        return [{
          payload: "9988",
          id: "downlink-2",
          counter: 236,
          createdAt: "2024-04-05T11:00:00.000Z"
        }];
      },
      async markDownlinkSent(deviceId, id) {
        events.push(`sent:${deviceId}:${id}`);
      }
    },
    downlinkDispatcher: {
      async schedule(context, downlink) {
        events.push(`schedule:${context.deviceId}:${downlink.uplinkAck}:${downlink.fCntDown}:${downlink.downlinks?.[0]}`);
      }
    },
    logger: {
      info() {},
      error() {}
    }
  });

  const result = await handler.handle(payload, {
    transport: "udp",
    receivedAt: Date.now(),
    sendDownlink: async () => {}
  });

  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(result.pendingChange, false);
  assert.deepEqual(events, [
    "forward:00001111:235",
    "ack:00001111:235",
    "schedule:00001111:12345:undefined:undefined"
  ]);
});

test("uplink handler does not resend a locally queued downlink that was just acknowledged", async () => {
  const firstPayload = Buffer.from(
    parser.encodeTlvPayload({
      version: 1,
      isConfirmed: true,
      stid: "00001111",
      fCntUp: 12345
    }, { direction: "uplink" }),
    "hex"
  );
  const ackPayload = Buffer.from(
    parser.encodeTlvPayload({
      version: 1,
      isConfirmed: true,
      stid: "00001111",
      fCntUp: 12346,
      downlinkAck: 235
    }, { direction: "uplink" }),
    "hex"
  );
  const scheduledDownlinks = [];

  const handler = new UplinkHandler({
    config: {
      payload: {
        encryptionAlgorithm: "aes-256-gcm"
      }
    },
    keyProvider: {
      async getKey() {
        throw new Error("Key lookup should not be called for plain TLV uplinks");
      }
    },
    forwarder: {
      async forward() {}
    },
    downlinkService: {
      async getPendingDownlinks() {
        return [
          {
            payload: "9988",
            id: "downlink-1",
            counter: 235,
            createdAt: "2024-04-05T11:00:00.000Z"
          },
          {
            payload: "AABB",
            id: "downlink-2",
            counter: 236,
            createdAt: "2024-04-05T12:00:00.000Z"
          }
        ];
      },
      async confirmAcknowledgedDownlink() {
        return [
          {
            payload: "9988",
            id: "downlink-1",
            counter: 235,
            createdAt: "2024-04-05T11:00:00.000Z"
          },
          {
            payload: "AABB",
            id: "downlink-2",
            counter: 236,
            createdAt: "2024-04-05T12:00:00.000Z"
          }
        ];
      },
      async markDownlinkSent() {}
    },
    downlinkDispatcher: {
      async schedule(context, downlink) {
        scheduledDownlinks.push(downlink);
      }
    },
    logger: {
      info() {},
      error() {}
    }
  });
  const context = {
    transport: "udp",
    receivedAt: Date.now(),
    sendDownlink: async () => {}
  };

  await handler.handle(firstPayload, context);
  await handler.handle(ackPayload, context);
  await new Promise((resolve) => setImmediate(resolve));

  assert.deepEqual(
    scheduledDownlinks.map((downlink) => ({
      uplinkAck: downlink.uplinkAck,
      fCntDown: downlink.fCntDown,
      payload: downlink.downlinks?.[0]
    })),
    [
      { uplinkAck: 12345, fCntDown: 235, payload: "9988" },
      { uplinkAck: 12346, fCntDown: 236, payload: "AABB" }
    ]
  );
  assert.equal(handler.pendingDownlinksByDevice.has("00001111"), false);
});

test("uplink handler does not wait for forwarding before checking config and scheduling ACK", async () => {
  const payload = Buffer.from(
    parser.encodeTlvPayload({
      version: 1,
      isConfirmed: true,
      stid: "00001111",
      fCntUp: 12345
    }, { direction: "uplink" }),
    "hex"
  );
  const events = [];

  const handler = new UplinkHandler({
    config: {
      payload: {
        encryptionAlgorithm: "aes-256-gcm"
      }
    },
    keyProvider: {
      async getKey() {
        throw new Error("Key lookup should not be called for plain TLV uplinks");
      }
    },
    forwarder: {
      forward(outbound) {
        events.push(`forward:${outbound.deviceId}`);
        return new Promise(() => {});
      }
    },
    downlinkService: {
      async getPendingDownlinks(deviceId) {
        events.push(`config:${deviceId}`);
        return [{
          payload: "9988",
          id: null,
          counter: 236,
          createdAt: "2024-04-05T11:00:00.000Z"
        }];
      },
      async markDownlinkSent(deviceId, id) {
        events.push(`confirm:${deviceId}:${id}`);
      }
    },
    downlinkDispatcher: {
      async schedule(context, downlink) {
        events.push(`schedule:${context.deviceId}:${downlink.uplinkAck}:${downlink.downlinks[0]}`);
      }
    },
    logger: {
      info() {},
      error() {}
    }
  });

  const result = await Promise.race([
    handler.handle(payload, {
      transport: "udp",
      receivedAt: Date.now(),
      sendDownlink: async () => {}
    }),
    new Promise((resolve) => setTimeout(() => resolve("timeout"), 50))
  ]);

  assert.notEqual(result, "timeout");
  assert.equal(result.pendingChange, true);
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(events, [
    "forward:00001111",
    "config:00001111",
    "schedule:00001111:12345:9988",
    "confirm:00001111:null"
  ]);
});

test("uplink handler retransmits the exact same downlink until max retries", async () => {
  const payload = Buffer.from(
    parser.encodeTlvPayload({
      version: 1,
      isConfirmed: true,
      stid: "00001111",
      fCntUp: 12345
    }, { direction: "uplink" }),
    "hex"
  );
  const sentPayloads = [];
  const logs = [];

  const handler = new UplinkHandler({
    config: {
      payload: {
        encryptionAlgorithm: "aes-256-gcm"
      },
      downlink: {
        retransmitWindowMs: 10,
        retransmitMaxRetries: 2
      }
    },
    keyProvider: {
      async getKey() {
        throw new Error("Key lookup should not be called for plain TLV uplinks");
      }
    },
    forwarder: {
      forward() {}
    },
    downlinkService: {
      async getPendingDownlinks() {
        return [{
          payload: "9988",
          id: "downlink-1",
          counter: 235,
          createdAt: "2024-04-05T11:00:00.000Z"
        }];
      },
      async markDownlinkSent() {}
    },
    downlinkDispatcher: new DownlinkDispatcher({
      parser,
      logger: {
        info(message, context) {
          logs.push({ message, context });
        },
        error() {}
      }
    }),
    logger: {
      info() {},
      warn() {},
      error() {}
    }
  });

  await handler.handle(payload, {
    transport: "udp",
    receivedAt: Date.now(),
    sendDownlink: async (downlinkPayload) => {
      sentPayloads.push(Buffer.from(downlinkPayload));
    }
  });
  await new Promise((resolve) => setTimeout(resolve, 35));

  assert.equal(sentPayloads.length, 3);
  assert.deepEqual(sentPayloads.map((entry) => entry.toString("hex")), [
    sentPayloads[0].toString("hex"),
    sentPayloads[0].toString("hex"),
    sentPayloads[0].toString("hex")
  ]);
  assert.deepEqual(
    logs.map((entry) => ({
      isRetry: entry.context.isRetry,
      retryAttempt: entry.context.retryAttempt
    })),
    [
      { isRetry: false, retryAttempt: undefined },
      { isRetry: true, retryAttempt: 1 },
      { isRetry: true, retryAttempt: 2 }
    ]
  );
});

test("uplink handler cancels retransmit when matching downlinkAck is received", async () => {
  const firstPayload = Buffer.from(
    parser.encodeTlvPayload({
      version: 1,
      isConfirmed: true,
      stid: "00001111",
      fCntUp: 12345
    }, { direction: "uplink" }),
    "hex"
  );
  const ackPayload = Buffer.from(
    parser.encodeTlvPayload({
      version: 1,
      stid: "00001111",
      downlinkAck: 235
    }, { direction: "uplink" }),
    "hex"
  );
  const sentPayloads = [];

  const handler = new UplinkHandler({
    config: {
      payload: {
        encryptionAlgorithm: "aes-256-gcm"
      },
      downlink: {
        retransmitWindowMs: 25,
        retransmitMaxRetries: 2
      }
    },
    keyProvider: {
      async getKey() {
        throw new Error("Key lookup should not be called for plain TLV uplinks");
      }
    },
    forwarder: {
      forward() {}
    },
    downlinkService: {
      async getPendingDownlinks() {
        return [{
          payload: "9988",
          id: "downlink-1",
          counter: 235,
          createdAt: "2024-04-05T11:00:00.000Z"
        }];
      },
      async confirmAcknowledgedDownlink(deviceId, downlinkAck) {
        assert.equal(deviceId, "00001111");
        assert.equal(downlinkAck, 235);
        return [];
      },
      async markDownlinkSent() {}
    },
    downlinkDispatcher: new DownlinkDispatcher({
      parser,
      logger: {
        info() {},
        error() {}
      }
    }),
    logger: {
      info() {},
      warn() {},
      error() {}
    }
  });
  const context = {
    transport: "udp",
    receivedAt: Date.now(),
    sendDownlink: async (downlinkPayload) => {
      sentPayloads.push(Buffer.from(downlinkPayload));
    }
  };

  await handler.handle(firstPayload, context);
  await new Promise((resolve) => setTimeout(resolve, 5));
  await handler.handle(ackPayload, context);
  await new Promise((resolve) => setTimeout(resolve, 40));

  assert.equal(sentPayloads.length, 1);
});

test("uplink handler cancels a retransmit when backend reconciliation cancels it", async () => {
  const payload = Buffer.from(
    parser.encodeTlvPayload({
      version: 1,
      isConfirmed: true,
      stid: "00001111",
      fCntUp: 12345
    }, { direction: "uplink" }),
    "hex"
  );
  const sentPayloads = [];
  const reconciliations = [];
  const logs = [];
  const handler = new UplinkHandler({
    config: {
      payload: { encryptionAlgorithm: "aes-256-gcm" },
      downlink: {
        retransmitWindowMs: 15,
        retransmitMaxRetries: 2,
        retransmitReconcileIntervalMs: 1
      }
    },
    keyProvider: { async getKey() {} },
    forwarder: { forward() {} },
    downlinkService: {
      async getPendingDownlinks() {
        return [{
          payload: "9988",
          id: "downlink-1",
          counter: 235,
          createdAt: "2024-04-05T11:00:00.000Z"
        }];
      },
      async markDownlinkSent() {},
      async reconcileRetransmits(deviceId, retransmits) {
        reconciliations.push({ deviceId, retransmits });
        return [{ counter: 235, action: "cancel", reason: "downlink_cancelled" }];
      }
    },
    downlinkDispatcher: new DownlinkDispatcher({
      parser,
      logger: { info() {}, error() {} }
    }),
    logger: {
      info(message, context) { logs.push({ message, context }); },
      warn() {},
      error() {}
    }
  });

  await handler.handle(payload, {
    transport: "udp",
    receivedAt: Date.now(),
    sendDownlink: async (downlinkPayload) => sentPayloads.push(Buffer.from(downlinkPayload))
  });
  await new Promise((resolve) => setTimeout(resolve, 45));

  assert.equal(sentPayloads.length, 1);
  assert.equal(reconciliations.length, 1);
  assert.equal(reconciliations[0].deviceId, "00001111");
  assert.equal(reconciliations[0].retransmits[0].id, "downlink-1");
  assert.equal(reconciliations[0].retransmits[0].counter, 235);
  assert.equal(
    logs.some((entry) => entry.message === "Downlink retransmit cancelled by backend"),
    true
  );
});

test("uplink handler decrypts encrypted TLV uplinks", async () => {
  const keyBytes = crypto.randomBytes(32);
  const message = buildEncryptedTlvMessage(
    "00001111",
    {
      deviceVersions: {
        _raw: "00000001000000020000000300000004"
      }
    },
    {
      isConfirmed: true,
      battery: 66,
      clickType: "double",
      fCntUp: 12355,
      fCntDown: 235
    },
    keyBytes
  );
  const requests = [];
  let sentDownlinkPayload;
  const originalFetch = global.fetch;

  global.fetch = async (url, options) => {
    const body = JSON.parse(options.body);
    requests.push({ url, method: options.method, body });

    if (url === "https://example.test/key") {
      return new Response(JSON.stringify({ key: keyBytes.toString("hex").toUpperCase() }), { status: 200 });
    }
    if (url === "https://example.test/forward") {
      return new Response(JSON.stringify({ accepted: true, echoedDeviceId: body.deviceId }), { status: 200 });
    }
    if (url === "https://example.test/config/get-pending-downlinks") {
      return new Response(JSON.stringify([]), { status: 200 });
    }

    throw new Error(`Unexpected url ${url}`);
  };

  try {
    const keyProvider = new HttpKeyProvider({
      url: "https://example.test/key",
      method: "POST",
      timeoutMs: 5000,
      deviceIdField: "deviceId",
      responseKeyField: "key"
    });
    const forwarder = new Forwarder({
      url: "https://example.test/forward",
      timeoutMs: 5000
    });
    const downlinkService = new DownlinkService({
      enabled: true,
      apiUrl: "https://example.test/config",
      timeoutMs: 5000
    });

    const logger = {
      info() {},
      error() {}
    };

    const downlinkDispatcher = new DownlinkDispatcher({
      logger,
      parser
    });

    const handler = new UplinkHandler({
      config: {
        payload: {
          encryptionAlgorithm: "aes-256-gcm"
        }
      },
      keyProvider,
      forwarder,
      downlinkService,
      downlinkDispatcher,
      logger
    });

    const result = await handler.handle(message.body, {
      transport: "udp",
      receivedAt: Date.now(),
      sendDownlink: async (payload) => {
        sentDownlinkPayload = payload;
      }
    });

    assert.equal(result.deviceId, "00001111");
    assert.deepEqual(result.decrypted.payload.stid, Buffer.from("00001111", "hex"));
    assert.equal(result.decrypted.payload.battery, 66);
    assert.equal(result.decrypted.payload.clickType, "double");
    assert.equal(result.decrypted.payload.fCntUp, 12355);
    assert.equal(result.decrypted.payload.fCntDown, 235);
    assert.deepEqual(result.decrypted.payload.deviceVersions, {
      hwVersion: "00000001",
      stmVersion: "00000002",
      nrfVersion: "00000003",
      espVersion: "00000004",
      _raw: "00000001000000020000000300000004"
    });
    assert.equal(result.pendingChange, false);
    const forwardRequest = requests.find((request) => request.url === "https://example.test/forward");
    assert.equal(Object.prototype.hasOwnProperty.call(forwardRequest.body, "metadata"), false);
    assert.equal(forwardRequest.body.deviceId, "00001111");
    assert.equal(forwardRequest.body.payload, message.body.toString("hex").toUpperCase());
    assert.equal(forwardRequest.body.uplink.stid, "00001111");
    assert.equal(forwardRequest.body.uplink.iv, Buffer.from(result.decrypted.payload.iv).toString("hex").toUpperCase());
    const keyRequest = requests.find((request) => request.url === "https://example.test/key");
    assert.deepEqual(keyRequest.body.metadata.deviceVersions, {
      hwVersion: "00000001",
      stmVersion: "00000002",
      nrfVersion: "00000003",
      espVersion: "00000004",
      _raw: "00000001000000020000000300000004"
    });
    const parsedDownlink = parser.parseTlvPayload(sentDownlinkPayload, { direction: "downlink" });
    assert.equal(parsedDownlink.version, 1);
    assert.deepEqual(parsedDownlink.stid, Buffer.from("00001111", "hex"));
    assert.equal(Object.prototype.hasOwnProperty.call(parsedDownlink, "uplinkAck"), false);
    assert.equal(Buffer.isBuffer(parsedDownlink.encryptedMessage), true);
    assert.equal(parsedDownlink.signature.length, 16);
    const decryptedDownlink = parser.decryptTlvUplinkMessage(parsedDownlink, keyBytes);
    assert.deepEqual(decryptedDownlink.payload.uplinkAck, 12355);
    assert.equal(Object.prototype.hasOwnProperty.call(decryptedDownlink.payload, "fCntDown"), false);
    assert.deepEqual(
      requests.map((request) => request.url).sort(),
      [
        "https://example.test/config/get-pending-downlinks",
        "https://example.test/forward",
        "https://example.test/key"
      ]
    );
  } finally {
    global.fetch = originalFetch;
  }
});

test("uplink handler logs crypto parameters before decrypting when enabled", async () => {
  const keyBytes = crypto.randomBytes(32);
  const receivedAt = Date.now();
  const message = buildEncryptedTlvMessage(
    "00001111",
    {},
    {
      fCntUp: 12345,
      payload: "010C00"
    },
    keyBytes
  );
  const debugLogs = [];
  const parsedMessage = parser.parseTlvUplinkMessage(message.body);

  const handler = new UplinkHandler({
    config: {
      logging: {
        includeCrypto: true
      },
      payload: {
        encryptionAlgorithm: "aes-256-gcm",
        allowedClockSkewSeconds: 60
      },
      keyProvider: {
        type: "HTTP"
      }
    },
    keyProvider: {
      async getKey(deviceId) {
        assert.equal(deviceId, "00001111");
        return keyBytes.toString("hex").toUpperCase();
      }
    },
    forwarder: {
      async forward() {}
    },
    downlinkService: {
      async getPendingDownlinks() {
        return [];
      }
    },
    downlinkDispatcher: {
      async schedule() {}
    },
    logger: {
      debug(messageText, context) {
        debugLogs.push({ message: messageText, context });
      },
      info() {},
      error() {}
    }
  });

  await handler.handle(message.body, {
    transport: "udp",
    receivedAt,
    sendDownlink: async () => {}
  });

  const cryptoLog = debugLogs.find((entry) => entry.message === "Uplink crypto parameters");
  assert.ok(cryptoLog);
  assert.equal(cryptoLog.context.deviceId, "00001111");
  assert.equal(cryptoLog.context.transport, "udp");
  assert.equal(cryptoLog.context.crypto.encrypted, true);
  assert.equal(cryptoLog.context.crypto.algorithm, "aes-256-gcm");
  assert.equal(cryptoLog.context.crypto.allowedClockSkewSeconds, 60);
  assert.equal(cryptoLog.context.crypto.cryptoMode, "AES-256 (PSK)");
  assert.equal(cryptoLog.context.crypto.key.required, true);
  assert.equal(cryptoLog.context.crypto.key.loaded, true);
  assert.equal(cryptoLog.context.crypto.key.material.hex, keyBytes.toString("hex").toUpperCase());
  assert.equal(cryptoLog.context.crypto.iv.value, parsedMessage.iv.toString("hex").toUpperCase());
  assert.equal(typeof cryptoLog.context.crypto.additionalAuthenticatedData, "string");
  assert.equal(typeof cryptoLog.context.crypto.encryptedMessage, "string");
  assert.equal(typeof cryptoLog.context.crypto.signature, "string");
  assert.equal(Object.prototype.hasOwnProperty.call(cryptoLog.context.crypto.plaintextFields, "encryptedMessage"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(cryptoLog.context.crypto.plaintextFields, "signature"), false);
});

test("uplink handler accepts plain hex TLV strings", async () => {
  const requests = [];
  const originalFetch = global.fetch;

  global.fetch = async (url, options) => {
    const body = JSON.parse(options.body);
    requests.push({ url, method: options.method, body });

    if (url === "https://example.test/forward") {
      return new Response(JSON.stringify({ accepted: true, echoedDeviceId: body.deviceId }), { status: 200 });
    }
    if (url === "https://example.test/config/get-pending-downlinks") {
      return new Response(JSON.stringify([]), { status: 200 });
    }
    if (url === "https://example.test/key") {
      throw new Error("Key lookup should not be called for plain TLV strings");
    }

    throw new Error(`Unexpected url ${url}`);
  };

  try {
    const keyProvider = new HttpKeyProvider({
      url: "https://example.test/key",
      method: "POST",
      timeoutMs: 5000,
      deviceIdField: "deviceId",
      responseKeyField: "key"
    });
    const forwarder = new Forwarder({
      url: "https://example.test/forward",
      timeoutMs: 5000
    });
    const downlinkService = new DownlinkService({
      enabled: true,
      apiUrl: "https://example.test/config",
      timeoutMs: 5000
    });
    const logger = {
      info() {},
      error() {}
    };
    const downlinkDispatcher = new DownlinkDispatcher({
      logger,
      parser
    });
    const handler = new UplinkHandler({
      config: {
        payload: {
          encryptionAlgorithm: "aes-256-gcm"
        }
      },
      keyProvider,
      forwarder,
      downlinkService,
      downlinkDispatcher,
      logger
    });

    const rawPayload = parser.encodeTlvPayload({
      version: 1,
      isConfirmed: true,
      stid: "00001111",
      fCntUp: 12345,
      fCntDown: 235,
      payload: "010C00"
    });

    const result = await handler.handle(
      rawPayload,
      {
        transport: "http",
        receivedAt: Date.now(),
        sendDownlink: async () => {}
      }
    );

    assert.equal(result.deviceId, "00001111");
    assert.deepEqual(result.decrypted.payload, {
      version: 1,
      isConfirmed: true,
      stid: Buffer.from("00001111", "hex"),
      fCntUp: 12345,
      fCntDown: 235,
      payload: Buffer.from("010C00", "hex")
    });
    const forwardRequest = requests.find((request) => request.url === "https://example.test/forward");
    assert.equal(Object.prototype.hasOwnProperty.call(forwardRequest.body, "metadata"), false);
    assert.equal(forwardRequest.body.deviceId, "00001111");
    assert.equal(forwardRequest.body.payload, rawPayload);
    assert.equal(forwardRequest.body.uplink.stid, "00001111");
    assert.equal(forwardRequest.body.uplink.fCntUp, 12345);
    assert.equal(forwardRequest.body.uplink.fCntDown, 235);
    assert.equal(forwardRequest.body.uplink.payload, "010C00");
    assert.deepEqual(
      requests.map((request) => request.url).sort(),
      [
        "https://example.test/config/get-pending-downlinks",
        "https://example.test/forward"
      ]
    );
  } finally {
    global.fetch = originalFetch;
  }
});

test("uplink handler accepts raw UDP TLV buffers", async () => {
  const requests = [];
  const originalFetch = global.fetch;

  global.fetch = async (url, options) => {
    const body = JSON.parse(options.body);
    requests.push({ url, method: options.method, body });

    if (url === "https://example.test/forward") {
      return new Response(JSON.stringify({ accepted: true, echoedDeviceId: body.deviceId }), { status: 200 });
    }
    if (url === "https://example.test/config/get-pending-downlinks") {
      return new Response(JSON.stringify([]), { status: 200 });
    }
    if (url === "https://example.test/key") {
      throw new Error("Key lookup should not be called for plain UDP TLV buffers");
    }

    throw new Error(`Unexpected url ${url}`);
  };

  try {
    const keyProvider = new HttpKeyProvider({
      url: "https://example.test/key",
      method: "POST",
      timeoutMs: 5000,
      deviceIdField: "deviceId",
      responseKeyField: "key"
    });
    const forwarder = new Forwarder({
      url: "https://example.test/forward",
      timeoutMs: 5000
    });
    const downlinkService = new DownlinkService({
      enabled: true,
      apiUrl: "https://example.test/config",
      timeoutMs: 5000
    });
    const logger = {
      info() {},
      error() {}
    };
    const downlinkDispatcher = new DownlinkDispatcher({
      logger,
      parser
    });
    const handler = new UplinkHandler({
      config: {
        payload: {
          encryptionAlgorithm: "aes-256-gcm"
        }
      },
      keyProvider,
      forwarder,
      downlinkService,
      downlinkDispatcher,
      logger
    });

    const rawPayload = parser.encodeTlvPayload({
      version: 1,
      isConfirmed: true,
      stid: "00001111",
      fCntUp: 12345,
      fCntDown: 235,
      payload: "010C00"
    });

    const result = await handler.handle(
      Buffer.from(rawPayload, "hex"),
      {
        transport: "udp",
        receivedAt: Date.now(),
        sendDownlink: async () => {}
      }
    );

    assert.equal(result.deviceId, "00001111");
    assert.deepEqual(result.decrypted.payload, {
      version: 1,
      isConfirmed: true,
      stid: Buffer.from("00001111", "hex"),
      fCntUp: 12345,
      fCntDown: 235,
      payload: Buffer.from("010C00", "hex")
    });
    const forwardRequest = requests.find((request) => request.url === "https://example.test/forward");
    assert.equal(forwardRequest.body.deviceId, "00001111");
    assert.equal(forwardRequest.body.payload, rawPayload);
    assert.equal(forwardRequest.body.uplink.stid, "00001111");
    assert.equal(forwardRequest.body.uplink.fCntUp, 12345);
    assert.equal(forwardRequest.body.uplink.fCntDown, 235);
    assert.equal(forwardRequest.body.uplink.payload, "010C00");
    assert.equal(forwardRequest.body.transport, "udp");
    assert.deepEqual(
      requests.map((request) => request.url).sort(),
      [
        "https://example.test/config/get-pending-downlinks",
        "https://example.test/forward"
      ]
    );
  } finally {
    global.fetch = originalFetch;
  }
});

test("uplink handler debug returns parsed payload without forwarding", async () => {
  const rawPayload = parser.encodeTlvPayload({
    version: 1,
    isConfirmed: true,
    stid: "00001111",
    fCntUp: 12345,
    payload: "010C00"
  }, { direction: "uplink" });
  const handler = new UplinkHandler({
    config: {
      payload: {
        encryptionAlgorithm: "aes-256-gcm",
        allowedClockSkewSeconds: 60
      },
      keyProvider: {
        type: "HTTP"
      }
    },
    keyProvider: {
      async getKey() {
        throw new Error("Key lookup should not be called for plain TLV debug");
      }
    },
    forwarder: {
      async forward() {
        throw new Error("Debug should not forward uplinks");
      }
    },
    downlinkService: {
      async getPendingDownlinks() {
        throw new Error("Debug should not check pending downlinks");
      }
    },
    downlinkDispatcher: {
      async schedule() {
        throw new Error("Debug should not schedule downlinks");
      }
    },
    logger: {
      info() {},
      error() {}
    }
  });

  const result = await handler.debug(rawPayload, {
    transport: "http",
    direction: "uplink",
    receivedAt: Date.UTC(2024, 3, 5, 12, 0, 0)
  });

  assert.equal(result.deviceId, "00001111");
  assert.equal(result.rawPayload.hex, rawPayload);
  assert.deepEqual(result.tlv, [
    { tag: "0x01", tagName: "version", length: 2, value: "0001" },
    { tag: "0x02", tagName: "isConfirmed", length: 1, value: "01" },
    { tag: "0x7E", tagName: "payload", length: 3, value: "010C00" },
    { tag: "0x1A", tagName: "stid", length: 4, value: "00001111" },
    { tag: "0x10", tagName: "fCntUp", length: 4, value: "00003039" }
  ]);
  assert.equal(result.parsedPayload.version, 1);
  assert.equal(result.parsedPayload.stid, "00001111");
  assert.equal(result.parsedPayload.fCntUp, 12345);
  assert.equal(result.parsedPayload.payload, "010C00");
  assert.equal(result.debug.encryption.encrypted, false);
  assert.equal(result.debug.key.loaded, false);
});

test("uplink handler debug returns plaintext fields when encrypted payload cannot decrypt", async () => {
  const encrypted = buildEncryptedTlvMessage(
    "00001111",
    {},
    {
      fCntUp: 12345,
      payload: "010C00"
    }
  );
  const wrongKey = crypto.randomBytes(32).toString("hex").toUpperCase();
  const handler = new UplinkHandler({
    config: {
      payload: {
        encryptionAlgorithm: "aes-256-gcm",
        allowedClockSkewSeconds: 60
      },
      keyProvider: {
        type: "HTTP"
      }
    },
    keyProvider: {
      async getKey(deviceId) {
        assert.equal(deviceId, "00001111");
        return wrongKey;
      }
    },
    forwarder: {
      async forward() {
        throw new Error("Debug should not forward uplinks");
      }
    },
    downlinkService: {
      async getPendingDownlinks() {
        throw new Error("Debug should not check pending downlinks");
      }
    },
    downlinkDispatcher: {
      async schedule() {
        throw new Error("Debug should not schedule downlinks");
      }
    },
    logger: {
      info() {},
      error() {}
    }
  });

  const result = await handler.debug(encrypted.body.toString("hex"), {
    transport: "http",
    direction: "uplink",
    receivedAt: Date.now()
  });

  assert.equal(result.deviceId, "00001111");
  assert.equal(result.parsedPayload.version, 1);
  assert.equal(result.parsedPayload.stid, "00001111");
  assert.equal(result.parsedPayload.cryptoMode, "AES-256 (PSK)");
  assert.equal(Object.prototype.hasOwnProperty.call(result.parsedPayload, "encryptedMessage"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(result.parsedPayload, "signature"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(result.parsedPayload, "fCntUp"), false);
  assert.equal(result.debug.encryption.encrypted, true);
  assert.equal(result.debug.encryption.decrypted, false);
  assert.match(result.debug.encryption.failure.message, /authenticate|Unsupported state/i);
  assert.equal(result.debug.key.loaded, true);
  const encryptedBlock = result.tlv.find((block) => block.tagName === "encryptedMessage");
  assert.equal(encryptedBlock.contents, undefined);
});

test("uplink handler debug authenticates empty encrypted TLV data", async () => {
  const message = buildEncryptedTlvMessage(
    "00001111",
    {
      battery: 55
    },
    {}
  );

  const handler = new UplinkHandler({
    config: {
      payload: {
        encryptionAlgorithm: "aes-256-gcm",
        allowedClockSkewSeconds: 60
      },
      keyProvider: {
        type: "HTTP"
      }
    },
    keyProvider: {
      async getKey() {
        return message.key;
      }
    },
    forwarder: {
      async forward() {
        throw new Error("Debug should not forward uplinks");
      }
    },
    downlinkService: {
      async getPendingDownlinks() {
        throw new Error("Debug should not check pending downlinks");
      }
    },
    downlinkDispatcher: {
      async schedule() {
        throw new Error("Debug should not schedule downlinks");
      }
    },
    logger: {
      info() {},
      error() {}
    }
  });

  const result = await handler.debug(message.body.toString("hex"), {
    transport: "http",
    direction: "uplink",
    receivedAt: Date.now()
  });

  assert.equal(result.deviceId, "00001111");
  assert.equal(result.parsedPayload.version, 1);
  assert.equal(result.parsedPayload.battery, 55);
  assert.equal(result.parsedPayload.cryptoMode, "AES-256 (PSK)");
  assert.equal(Object.prototype.hasOwnProperty.call(result.parsedPayload, "encryptedMessage"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(result.parsedPayload, "signature"), false);
  assert.equal(result.debug.encryption.encrypted, true);
  assert.equal(result.debug.encryption.decrypted, true);
  assert.equal(result.debug.encryption.failure, null);
  assert.equal(result.debug.encryption.decryptedPlaintext, "");
  assert.equal(result.debug.key.required, true);
  assert.equal(result.debug.key.loaded, true);
  const encryptedBlock = result.tlv.find((block) => block.tagName === "encryptedMessage");
  assert.deepEqual(encryptedBlock.contents, []);
});
