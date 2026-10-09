const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const { DownlinkDispatcher } = require("../src/services/downlinkDispatcher");
const parser = require("../src/parser");

test("downlink dispatcher logs structured downlink and hex payload", async () => {
  const logs = [];
  const dispatcher = new DownlinkDispatcher({
    logger: {
      info(message, context) {
        logs.push({ message, context });
      },
      error() {}
    },
    parser
  });
  const downlinkRequest = {
    uplinkAck: 1234,
    downlinks: [Buffer.from("12230000010502", "hex")]
  };
  let sentPayload;

  await dispatcher.schedule({
    deviceId: "00001111",
    transport: "http",
    receivedAt: Date.now(),
    sendDownlink: async (payload) => {
      sentPayload = payload;
    }
  }, downlinkRequest);

  assert.equal(logs.length, 1);
  assert.equal(logs[0].message, "Downlink sent");
  assert.deepEqual(logs[0].context, {
    deviceId: "00001111",
    transport: "http",
    downlinkRequest,
    downlink: Buffer.from("12230000010502", "hex"),
    downlinkHex: sentPayload.toString("hex").toUpperCase(),
    isRetry: false
  });
});

test("downlink dispatcher logs compact retry info when enabled", async () => {
  const logs = [];
  const dispatcher = new DownlinkDispatcher({
    logger: {
      info(message, context) {
        logs.push({ message, context });
      },
      error() {}
    },
    parser,
    includeRetryInfo: true
  });
  const downlinkRequest = {
    uplinkAck: 1234,
    fCntDown: 235,
    downlinks: [Buffer.from("12230000010502", "hex")]
  };

  await dispatcher.schedule({
    deviceId: "00001111",
    transport: "udp",
    sendDownlink: async () => {}
  }, downlinkRequest, {
    isRetry: true,
    retryAttempt: 2
  });

  assert.equal(logs.length, 2);
  assert.equal(logs[0].message, "Retry info");
  assert.deepEqual(logs[0].context, {
    deviceId: "00001111",
    transport: "udp",
    event: "downlink_tx",
    retry: "fCntUp=      fCntDown=  235 downlinkAck=      uplinkAck= 1234 retransmitCount=    2"
  });
  assert.equal(logs[1].message, "Downlink sent");
});

test("downlink dispatcher does not log encrypted downlink crypto parameters by default", async () => {
  const debugLogs = [];
  const dispatcher = new DownlinkDispatcher({
    logger: {
      debug(message, context) {
        debugLogs.push({ message, context });
      },
      info() {},
      error() {}
    },
    parser
  });
  const key = crypto.randomBytes(32);
  const iv = Buffer.from("00112233445566778899AABB", "hex");
  const downlinkRequest = {
    uplinkAck: 1234,
    fCntDown: 235,
    downlinks: [Buffer.from("12230000010502", "hex")],
    encryption: {
      key,
      version: 1,
      stid: "00001111",
      iv
    }
  };
  let sentPayload;

  await dispatcher.schedule({
    deviceId: "00001111",
    transport: "udp",
    sendDownlink: async (payload) => {
      sentPayload = payload;
    }
  }, downlinkRequest);

  assert.ok(sentPayload);
  assert.equal(debugLogs.length, 0);
});

test("downlink dispatcher logs encrypted downlink crypto parameters at debug level when enabled", async () => {
  const debugLogs = [];
  const dispatcher = new DownlinkDispatcher({
    logger: {
      debug(message, context) {
        debugLogs.push({ message, context });
      },
      info() {},
      error() {}
    },
    parser,
    includeCrypto: true
  });
  const key = crypto.randomBytes(32);
  const iv = Buffer.from("00112233445566778899AABB", "hex");
  const downlinkRequest = {
    uplinkAck: 1234,
    fCntDown: 235,
    downlinks: [Buffer.from("12230000010502", "hex")],
    encryption: {
      key,
      version: 1,
      stid: "00001111",
      iv
    }
  };
  let sentPayload;

  await dispatcher.schedule({
    deviceId: "00001111",
    transport: "udp",
    sendDownlink: async (payload) => {
      sentPayload = payload;
    }
  }, downlinkRequest);

  const parsed = parser.parseTlvPayload(sentPayload, { direction: "downlink" });
  const aad = parser.getTlvAdditionalAuthenticatedData(parsed);

  assert.equal(debugLogs.length, 1);
  assert.equal(debugLogs[0].message, "Downlink crypto parameters");
  assert.deepEqual(debugLogs[0].context, {
    deviceId: "00001111",
    transport: "udp",
    crypto: {
      input: parser.formatDownlinkMessage({
        uplinkAck: 1234,
        fCntDown: 235,
        downlinks: [Buffer.from("12230000010502", "hex")]
      }).toString("hex").toUpperCase(),
      aad: aad.toString("hex").toUpperCase(),
      iv: iv.toString("hex").toUpperCase(),
      ciphertext: parsed.encryptedMessage.toString("hex").toUpperCase()
    }
  });
});
