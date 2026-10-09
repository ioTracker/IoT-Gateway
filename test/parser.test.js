const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const {
  encodeTlvPayload,
  parseTlvPayload,
  parseTlvUplinkMessage,
  buildTlvMetadata,
  decryptTlvUplinkMessage,
  getTlvAdditionalAuthenticatedData,
  formatDownlinkMessage,
  formatEncryptedDownlinkMessage
} = require("../src/parser");

function encodeTagHeaderValue(value) {
  if (value >= 0x01 && value <= 0x7F) {
    return Buffer.from([value]);
  }

  return Buffer.from([
    (value >> 8) & 0xFF,
    value & 0xFF
  ]);
}

function encodeLengthHeaderValue(value) {
  if (value <= 0x7F) {
    return Buffer.from([value]);
  }

  const encodedValue = value + 0x7F80;
  return Buffer.from([
    (encodedValue >> 8) & 0xFF,
    encodedValue & 0xFF
  ]);
}

function tlv(tag, value) {
  let valueBuffer;
  if (Buffer.isBuffer(value)) {
    valueBuffer = value;
  } else if (value instanceof Uint8Array) {
    valueBuffer = Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  } else {
    const normalizedValue = value === null || value === undefined ? "" : String(value);
    valueBuffer = Buffer.from(normalizedValue, "utf8");
  }

  return Buffer.concat([
    encodeTagHeaderValue(tag),
    encodeLengthHeaderValue(valueBuffer.length),
    valueBuffer
  ]);
}

function oldFourByteTagTlv(tag, value) {
  const valueBuffer = Buffer.from(value);
  return Buffer.concat([
    Buffer.from([
      0x80,
      0x00,
      (tag >> 8) & 0xFF,
      tag & 0xFF
    ]),
    encodeLengthHeaderValue(valueBuffer.length),
    valueBuffer
  ]);
}

function buildIv(timestamp) {
  const iv = Buffer.alloc(12);
  crypto.randomBytes(8).copy(iv, 0);
  iv.writeUInt32BE(timestamp, 8);
  return iv;
}

function buildEncryptedTlvMessage(outerFields, innerFields, key, options = {}) {
  const actualKey = key || crypto.randomBytes(32);
  const timestamp = options.timestamp === undefined
    ? Math.floor(Date.now() / 1000)
    : options.timestamp;
  const plaintextFields = {
    cryptoMode: 1,
    ...outerFields
  };
  plaintextFields.iv = buildIv(timestamp);
  const aad = Buffer.from(
    encodeTlvPayload(plaintextFields, { direction: "uplink" }),
    "hex"
  );
  const plaintext = Buffer.from(
    encodeTlvPayload(innerFields, { direction: "uplink" }),
    "hex"
  );
  const cipher = crypto.createCipheriv("aes-256-gcm", actualKey, plaintextFields.iv);
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    key: actualKey.toString("hex").toUpperCase(),
    payload: Buffer.from(
      encodeTlvPayload({
        ...plaintextFields,
        signature: authTag,
        encryptedMessage: encrypted
      }, { direction: "uplink" }),
      "hex"
    )
  };
}

test("parseTlvUplinkMessage returns the full plain TLV uplink object", () => {
  const payload = Buffer.from(
    encodeTlvPayload({
      version: 1,
      isConfirmed: true,
      stid: "00001111",
      battery: 87,
      clickType: "double"
    }, { direction: "uplink" }),
    "hex"
  );

  const message = parseTlvUplinkMessage(payload);
  const decrypted = decryptTlvUplinkMessage(message, null);

  assert.deepEqual(decrypted.payload, {
    version: 1,
    isConfirmed: true,
    stid: Buffer.from("00001111", "hex"),
    battery: 87,
    clickType: "double"
  });
});

test("parseTlvUplinkMessage decodes struct fields and preserves their raw hex", () => {
  const payload = Buffer.concat([
    tlv(0x1D, Buffer.from("0102030405060708090A0B0C0D0E0F10", "hex")),
    tlv(0x8003, Buffer.from("57FD1234", "hex"))
  ]);

  const message = parseTlvUplinkMessage(payload);

  assert.deepEqual(message.deviceVersions, {
    hwVersion: "01020304",
    stmVersion: "05060708",
    nrfVersion: "090A0B0C",
    espVersion: "0D0E0F10",
    _raw: "0102030405060708090A0B0C0D0E0F10"
  });
  assert.deepEqual(message.batteryStatus, {
    socDisplay: 87,
    flags: {
      lowTemp: true,
      veryLowTemp: false,
      replaceSoon: true,
      highStandbyCurrent: true,
      batEvalState: "bad",
      esrQualityLimited: true,
      impedanceSocLimited: true
    },
    daysRemaining: 0x1234,
    _raw: "57FD1234"
  });
});

test("parseTlvUplinkMessage decodes battery status FD00000B", () => {
  const message = parseTlvUplinkMessage(
    tlv(0x8003, Buffer.from("FD00000B", "hex"))
  );

  assert.deepEqual(message.batteryStatus, {
    socDisplay: 253,
    flags: {
      lowTemp: false,
      veryLowTemp: false,
      replaceSoon: false,
      highStandbyCurrent: false,
      batEvalState: "inUse",
      esrQualityLimited: false,
      impedanceSocLimited: false
    },
    daysRemaining: 11,
    _raw: "FD00000B"
  });
});

test("parseTlvUplinkMessage decodes battery status F8400002", () => {
  const message = parseTlvUplinkMessage(
    tlv(0x8003, Buffer.from("F8400002", "hex"))
  );

  assert.deepEqual(message.batteryStatus, {
    socDisplay: 248,
    flags: {
      lowTemp: false,
      veryLowTemp: false,
      replaceSoon: false,
      highStandbyCurrent: false,
      batEvalState: "inUse",
      esrQualityLimited: true,
      impedanceSocLimited: false
    },
    daysRemaining: 2,
    _raw: "F8400002"
  });
});

test("parseTlvUplinkMessage rejects structs with an unexpected length", () => {
  assert.throws(
    () => parseTlvUplinkMessage(tlv(0x8003, Buffer.from("5705", "hex"))),
    /batteryStatus.*must have length 4/
  );
});

test("parseTlvUplinkMessage decodes the packed big-endian cellular status struct", () => {
  const message = parseTlvUplinkMessage(
    Buffer.from("A0041301F7010714000000CC0004533901915902FFFF", "hex")
  );

  assert.deepEqual(message.cellularStatus, {
    version: 1,
    valid: {
      ceregStat: true,
      rat: true,
      band: true,
      earfcn: false,
      plmn: true,
      tac: true,
      cellId: true,
      cesq: true
    },
    ceregStat: "REGISTERED_HOME",
    rat: "LTE-M",
    band: 20,
    earfcn: 0,
    mcc: 204,
    mnc: 4,
    tac: 0x5339,
    cellId: 0x01915902,
    cellENB: 102745,
    cellSector: 2,
    rsrq: 0xFF,
    rsrp: 0xFF,
    _raw: "01F7010714000000CC0004533901915902FFFF"
  });
});

test("parseTlvUplinkMessage rejects cell status with an unexpected length", () => {
  assert.throws(
    () => parseTlvUplinkMessage(tlv(0xA004, Buffer.alloc(18))),
    /cellularStatus.*must have length 19/
  );
});

test("buildTlvMetadata serializes first-boot device fields as hex strings", () => {
  const metadata = buildTlvMetadata({
    version: 1,
    imei: Buffer.from("123456789012345F", "hex"),
    iccid: Buffer.from("8944501234567890123F", "hex"),
    versions: Buffer.from("00000001000000020000000300000004", "hex"),
    battery: 88,
    clickType: "single"
  });

  assert.deepEqual(metadata, {
    version: 1,
    imei: "123456789012345F",
    iccid: "8944501234567890123F",
    versions: "00000001000000020000000300000004",
    battery: 88,
    clickType: "single"
  });
});

test("buildTlvMetadata sends decoded device versions as an object", () => {
  const deviceVersions = {
    hwVersion: "01020304",
    stmVersion: "05060708",
    nrfVersion: "090A0B0C",
    espVersion: "0D0E0F10",
    _raw: "0102030405060708090A0B0C0D0E0F10"
  };

  assert.deepEqual(buildTlvMetadata({ version: 1, deviceVersions }), {
    version: 1,
    deviceVersions
  });
});

test("parseTlvUplinkMessage decrypts only the encrypted TLV field", () => {
  const message = buildEncryptedTlvMessage(
    {
      version: 1,
      stid: "00001111"
    },
    {
      battery: 55,
      clickType: "long",
      payload: Buffer.from("ABCD", "hex")
    }
  );

  const parsed = parseTlvUplinkMessage(message.payload);
  const decrypted = decryptTlvUplinkMessage(parsed, message.key);

  assert.deepEqual(decrypted.payload, {
    version: 1,
    stid: Buffer.from("00001111", "hex"),
    iv: parsed.iv,
    cryptoMode: "AES-256 (PSK)",
    battery: 55,
    clickType: "long",
    payload: Buffer.from("ABCD", "hex")
  });
  assert.equal(Object.prototype.hasOwnProperty.call(decrypted.payload, "encryptedMessage"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(decrypted.payload, "signature"), false);
});

test("decryptTlvUplinkMessage excludes signature from reconstructed AAD", () => {
  const message = buildEncryptedTlvMessage(
    {
      version: 1,
      stid: "00001111"
    },
    {
      battery: 55
    }
  );

  const parsed = parseTlvUplinkMessage(message.payload);
  const messageWithoutRawAad = { ...parsed };
  const decrypted = decryptTlvUplinkMessage(messageWithoutRawAad, message.key);

  assert.equal(decrypted.payload.battery, 55);
});

test("decryptTlvUplinkMessage accepts empty encryptedMessage for authentication-only messages", () => {
  const message = buildEncryptedTlvMessage(
    {
      version: 1,
      stid: "00001111",
      battery: 55
    },
    {}
  );

  const parsed = parseTlvUplinkMessage(message.payload);
  const decrypted = decryptTlvUplinkMessage(parsed, message.key);

  assert.deepEqual(decrypted.payload, {
    version: 1,
    stid: Buffer.from("00001111", "hex"),
    battery: 55,
    iv: parsed.iv,
    cryptoMode: "AES-256 (PSK)"
  });
  assert.equal(decrypted.plaintext, "");
});

test("decryptTlvUplinkMessage uses exact raw TLV bytes for AAD", () => {
  const key = crypto.randomBytes(32);
  const iv = buildIv(Math.floor(Date.now() / 1000));
  const aad = Buffer.concat([
    tlv(0x01, Buffer.from("01", "hex")),
    tlv(0x1A, Buffer.from("00001111", "hex")),
    tlv(0x21, iv),
    tlv(0x22, Buffer.from([0x01]))
  ]);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(aad);
  cipher.final();
  const signature = cipher.getAuthTag();
  const payload = Buffer.concat([
    aad,
    tlv(0x23, signature),
    tlv(0x7F, Buffer.alloc(0))
  ]);

  const parsed = parseTlvUplinkMessage(payload);
  const decrypted = decryptTlvUplinkMessage(parsed, key);

  assert.equal(getTlvAdditionalAuthenticatedData(parsed).toString("hex").toUpperCase(), aad.toString("hex").toUpperCase());
  assert.equal(aad.subarray(0, 3).toString("hex").toUpperCase(), "010101");
  assert.equal(decrypted.payload.version, 1);
});

test("decryptTlvUplinkMessage requires hex string keys", () => {
  const message = buildEncryptedTlvMessage(
    {
      version: 1,
      stid: "00001111"
    },
    {
      battery: 55
    }
  );

  const parsed = parseTlvUplinkMessage(message.payload);

  assert.throws(
    () => decryptTlvUplinkMessage(parsed, "not-hex"),
    /Encryption key must be an even-length hexadecimal string/
  );
});

test("decryptTlvUplinkMessage requires cryptoMode for encrypted TLV fields", () => {
  const message = buildEncryptedTlvMessage(
    {
      version: 1,
      stid: "00001111"
    },
    {
      battery: 55
    }
  );

  const parsed = parseTlvUplinkMessage(message.payload);
  delete parsed.cryptoMode;

  assert.throws(
    () => decryptTlvUplinkMessage(parsed, message.key),
    /contains encryptedMessage but does not contain cryptoMode/
  );
});

test("decryptTlvUplinkMessage only accepts AES-256 PSK cryptoMode for encrypted TLV fields", () => {
  const message = buildEncryptedTlvMessage(
    {
      version: 1,
      stid: "00001111",
      cryptoMode: 2
    },
    {
      battery: 55
    }
  );

  const parsed = parseTlvUplinkMessage(message.payload);

  assert.throws(
    () => decryptTlvUplinkMessage(parsed, message.key),
    /cryptoMode is not AES-256 \(PSK\)/
  );
});

test("decryptTlvUplinkMessage requires signature for encrypted TLV fields", () => {
  const message = buildEncryptedTlvMessage(
    {
      version: 1,
      stid: "00001111"
    },
    {
      battery: 55
    }
  );

  const parsed = parseTlvUplinkMessage(message.payload);
  delete parsed.signature;

  assert.throws(
    () => decryptTlvUplinkMessage(parsed, message.key),
    /contains encryptedMessage but does not contain signature/
  );
});

test("decryptTlvUplinkMessage requires a 16-byte signature for encrypted TLV fields", () => {
  const message = buildEncryptedTlvMessage(
    {
      version: 1,
      stid: "00001111"
    },
    {
      battery: 55
    }
  );

  const parsed = parseTlvUplinkMessage(message.payload);
  parsed.signature = parsed.signature.subarray(0, 15);

  assert.throws(
    () => decryptTlvUplinkMessage(parsed, message.key),
    /signature is not a 16-byte AES-GCM auth tag/
  );
});

test("decryptTlvUplinkMessage requires a 96-bit iv for encrypted TLV fields", () => {
  const message = buildEncryptedTlvMessage(
    {
      version: 1,
      stid: "00001111"
    },
    {
      battery: 55
    }
  );

  const parsed = parseTlvUplinkMessage(message.payload);
  parsed.iv = parsed.iv.subarray(0, 11);

  assert.throws(
    () => decryptTlvUplinkMessage(parsed, message.key),
    /iv is not 96 bits/
  );
});

test("decryptTlvUplinkMessage rejects iv timestamps outside the allowed clock skew", () => {
  const currentTimestampSeconds = 1712345678;
  const message = buildEncryptedTlvMessage(
    {
      version: 1,
      stid: "00001111"
    },
    {
      battery: 55
    },
    undefined,
    { timestamp: currentTimestampSeconds - 61 }
  );

  const parsed = parseTlvUplinkMessage(message.payload);

  assert.throws(
    () => decryptTlvUplinkMessage(parsed, message.key, {
      allowedClockSkewSeconds: 60,
      currentTimestampSeconds
    }),
    /iv timestamp is outside the allowed clock skew/
  );
});

test("decryptTlvUplinkMessage skips iv timestamp validation when unsyncedClock is set", () => {
  const currentTimestampSeconds = 1712345678;
  const message = buildEncryptedTlvMessage(
    {
      version: 1,
      stid: "00001111",
      unsyncedClock: true
    },
    {
      battery: 55
    },
    undefined,
    { timestamp: currentTimestampSeconds - 3600 }
  );

  const parsed = parseTlvUplinkMessage(message.payload);
  const decrypted = decryptTlvUplinkMessage(parsed, message.key, {
    allowedClockSkewSeconds: 60,
    currentTimestampSeconds
  });

  assert.equal(decrypted.payload.unsyncedClock, true);
  assert.equal(decrypted.payload.battery, 55);
});

test("decryptTlvUplinkMessage authenticates plaintext TLV fields as AES-GCM AAD", () => {
  const message = buildEncryptedTlvMessage(
    {
      version: 1,
      stid: "00001111"
    },
    {
      battery: 55
    }
  );

  const tamperedPayload = Buffer.from(message.payload);
  const stidTlvOffset = tamperedPayload.indexOf(Buffer.from("1A0400001111", "hex"));
  assert.notEqual(stidTlvOffset, -1);
  const stidValueOffset = stidTlvOffset + 2;
  tamperedPayload[stidValueOffset] ^= 0x01;
  const parsed = parseTlvUplinkMessage(tamperedPayload);

  assert.throws(
    () => decryptTlvUplinkMessage(parsed, message.key),
    /Unsupported state or unable to authenticate data/
  );
});

test("formatDownlinkMessage returns a TLV downlink ACK with optional payloads", async () => {
  const buffer = formatDownlinkMessage({
    uplinkAck: 1234,
    fCntDown: 235,
    downlinks: ["12230000010502", { intervalSeconds: 60 }]
  });
  const parsed = parseTlvPayload(buffer, { direction: "downlink" });

  assert.deepEqual(parsed, {
    uplinkAck: 1234,
    fCntDown: 235,
    downlinks: [
      Buffer.from("12230000010502", "hex"),
      Buffer.from(JSON.stringify({ intervalSeconds: 60 }), "utf8")
    ]
  });
});

test("formatDownlinkMessage can return downlinks without an uplink ACK", async () => {
  const buffer = formatDownlinkMessage({
    fCntDown: 236,
    downlinks: ["12230000010502", "9988"]
  });
  const parsed = parseTlvPayload(buffer, { direction: "downlink" });

  assert.deepEqual(parsed, {
    fCntDown: 236,
    downlinks: [
      Buffer.from("12230000010502", "hex"),
      Buffer.from("9988", "hex")
    ]
  });
});

test("formatEncryptedDownlinkMessage encrypts the ACK with version and stid as AAD", () => {
  const key = crypto.randomBytes(32);
  const iv = buildIv(Math.floor(Date.now() / 1000));
  const buffer = formatEncryptedDownlinkMessage({
    uplinkAck: 1234,
    encryption: {
      key,
      version: 1,
      stid: "00001111",
      iv
    }
  });
  const parsed = parseTlvPayload(buffer, { direction: "downlink" });

  assert.equal(parsed.version, 1);
  assert.deepEqual(parsed.stid, Buffer.from("00001111", "hex"));
  assert.deepEqual(parsed.iv, iv);
  assert.equal(parsed.cryptoMode, "AES-256 (PSK)");
  assert.equal(Buffer.isBuffer(parsed.encryptedMessage), true);
  assert.equal(parsed.signature.length, 16);
  assert.equal(Object.prototype.hasOwnProperty.call(parsed, "uplinkAck"), false);

  const decrypted = decryptTlvUplinkMessage(parsed, key);

  assert.deepEqual(decrypted.payload.uplinkAck, 1234);
  assert.equal(
    decrypted.plaintext,
    formatDownlinkMessage({ uplinkAck: 1234 }).toString("hex").toUpperCase()
  );
});

test("formatEncryptedDownlinkMessage authenticates plaintext downlink TLV fields as AES-GCM AAD", () => {
  const key = crypto.randomBytes(32);
  const iv = buildIv(Math.floor(Date.now() / 1000));
  const buffer = formatEncryptedDownlinkMessage({
    uplinkAck: 1234,
    fCntDown: 235,
    downlinks: ["12230000010502"],
    encryption: {
      key,
      version: 1,
      stid: "00001111",
      iv
    }
  });

  const parsed = parseTlvPayload(buffer, { direction: "downlink" });
  assert.deepEqual(decryptTlvUplinkMessage(parsed, key).payload.uplinkAck, 1234);

  const tamperedPayload = Buffer.from(buffer);
  const stidTlvOffset = tamperedPayload.indexOf(Buffer.from("1A0400001111", "hex"));
  assert.notEqual(stidTlvOffset, -1);
  const stidValueOffset = stidTlvOffset + 2;
  tamperedPayload[stidValueOffset] ^= 0x01;

  const tampered = parseTlvPayload(tamperedPayload, { direction: "downlink" });
  assert.throws(
    () => decryptTlvUplinkMessage(tampered, key),
    /Unsupported state or unable to authenticate data/
  );
});

test("parseTlvPayload parses an uplink ArrayBuffer into a schema-named object", () => {
  const payload = Buffer.concat([
    tlv(0x01, Buffer.from([0x01])),
    tlv(0x02, Buffer.from([0x01])),
    tlv(0x1A, Buffer.from("00001111", "hex")),
    tlv(0x8002, Buffer.from([0x01])),
    tlv(0x7E, Buffer.from("ABC123", "hex"))
  ]);

  const parsed = parseTlvPayload(
    payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength)
  );

  assert.deepEqual(parsed, {
    version: 1,
    isConfirmed: true,
    stid: Buffer.from("00001111", "hex"),
    clickType: "single",
    payload: Buffer.from("ABC123", "hex")
  });
});

test("parseTlvPayload always returns arrays for repeatable downlink fields", () => {
  const payload = Buffer.concat([
    tlv(0x01, Buffer.from([89])),
    tlv(0x14, Buffer.from("0000EA", "hex")),
    tlv(0x7C, Buffer.from("12230000010502", "hex")),
    tlv(0x7C, Buffer.from("9988", "hex"))
  ]);

  const parsed = parseTlvPayload(payload);

  assert.deepEqual(parsed, {
    version: 89,
    uplinkAck: 234,
    downlinks: [Buffer.from("12230000010502", "hex"), Buffer.from("9988", "hex")]
  });
});

test("parseTlvPayload rejects duplicate values for non-repeatable fields", () => {
  const payload = Buffer.concat([
    tlv(0x01, Buffer.from([87])),
    tlv(0x01, Buffer.from([88]))
  ]);

  assert.throws(() => parseTlvPayload(payload), /may not appear multiple times/);
});

test("parseTlvPayload returns buffers for binary fields", () => {
  const signature = Buffer.from("00112233445566778899AABBCCDDEEFF", "hex");
  const payload = Buffer.concat([
    tlv(0x01, Buffer.from([0x02])),
    tlv(0x23, signature)
  ]);

  const parsed = parseTlvPayload(payload);

  assert.equal(parsed.version, 2);
  assert.deepEqual(parsed.signature, signature);
});

test("encodeTlvPayload encodes an uplink object to a hex payload", () => {
  const encoded = encodeTlvPayload({
    version: 1,
    isConfirmed: true,
    stid: "00001111",
    clickType: "double",
    payload: "ABC123"
  }, { direction: "uplink" });

  assert.equal(
    encoded,
    Buffer.concat([
      tlv(0x01, Buffer.from("0001", "hex")),
      tlv(0x02, Buffer.from([0x01])),
      tlv(0x7E, Buffer.from("ABC123", "hex")),
      tlv(0x1A, Buffer.from("00001111", "hex")),
      tlv(0x8002, Buffer.from([0x02]))
    ]).toString("hex").toUpperCase()
  );
});

test("encodeTlvPayload uses fixed-width integer payloads from uint and int types", () => {
  const encoded = encodeTlvPayload({
    version: 1,
    isConfirmed: true,
    fCntUp: 12345,
    retransmitCount: 12345,
    battery: 87,
    rsrp: -95,
    rsrq: -12
  }, { direction: "uplink" });

  assert.equal(
    encoded,
    Buffer.concat([
      tlv(0x01, Buffer.from("0001", "hex")),
      tlv(0x02, Buffer.from([0x01])),
      tlv(0x10, Buffer.from("00003039", "hex")),
      tlv(0x15, Buffer.from("00003039", "hex")),
      tlv(0xA002, Buffer.from("FFA1", "hex")),
      tlv(0xA003, Buffer.from("FFF4", "hex")),
      tlv(0x8001, Buffer.from("57", "hex"))
    ]).toString("hex").toUpperCase()
  );

  assert.deepEqual(parseTlvPayload(Buffer.from(encoded, "hex")), {
    version: 1,
    isConfirmed: true,
    fCntUp: 12345,
    retransmitCount: 12345,
    rsrp: -95,
    rsrq: -12,
    battery: 87
  });
});

test("encodeTlvPayload rejects integers outside their fixed-width spec range", () => {
  assert.throws(
    () => encodeTlvPayload({ battery: 256 }, { direction: "uplink" }),
    /must be between 0 and 255/
  );
  assert.throws(
    () => encodeTlvPayload({ rsrp: -32769 }, { direction: "uplink" }),
    /must be between -32768 and 32767/
  );
});

test("parseTlvPayload decodes integer payloads using the TLV length field", () => {
  const payload = tlv(0x10, Buffer.from("3039", "hex"));

  assert.deepEqual(parseTlvPayload(payload), { fCntUp: 12345 });
});

test("encodeTlvPayload accepts arrays for repeatable fields and round-trips through the parser", () => {
  const encoded = encodeTlvPayload({
    version: 89,
    uplinkAck: 234,
    downlinks: ["12230000010502", "9988"]
  }, { direction: "downlink" });

  const parsed = parseTlvPayload(Buffer.from(encoded, "hex"));

  assert.deepEqual(parsed, {
    version: 89,
    uplinkAck: 234,
    downlinks: [Buffer.from("12230000010502", "hex"), Buffer.from("9988", "hex")]
  });
});

test("parseTlvPayload decodes two-byte tag and length headers", () => {
  const longDownlink = Buffer.alloc(130, 0xAB);
  const payload = Buffer.concat([
    tlv(0x01, Buffer.from([89])),
    tlv(0x7C, longDownlink)
  ]);

  const parsed = parseTlvPayload(payload);

  assert.deepEqual(parsed, {
    version: 89,
    downlinks: [longDownlink]
  });
});

test("parseTlvPayload decodes extended tags as raw two-byte tag values", () => {
  const payload = Buffer.concat([
    tlv(0x8001, Buffer.from([87])),
    tlv(0xA002, Buffer.from("FFA1", "hex"))
  ]);

  const parsed = parseTlvPayload(payload);

  assert.deepEqual(parsed, {
    battery: 87,
    rsrp: -95
  });
  assert.equal(payload.subarray(0, 4).toString("hex").toUpperCase(), "80010157");
  assert.equal(payload.subarray(4, 8).toString("hex").toUpperCase(), "A00202FF");
});

test("parseTlvPayload decodes extended lengths with the 0x8000 to 128 offset", () => {
  const length127 = tlv(0x7C, Buffer.alloc(127, 0x7A));
  const length128 = tlv(0x7C, Buffer.alloc(128, 0x80));
  const length129 = tlv(0x7C, Buffer.alloc(129, 0x81));
  const length32895 = tlv(0x7C, Buffer.alloc(32895, 0xFF));
  const parsed = parseTlvPayload(Buffer.concat([
    length127,
    length128,
    length129,
    length32895
  ]));

  assert.equal(length127.subarray(0, 2).toString("hex").toUpperCase(), "7C7F");
  assert.equal(length128.subarray(0, 3).toString("hex").toUpperCase(), "7C8000");
  assert.equal(length129.subarray(0, 3).toString("hex").toUpperCase(), "7C8001");
  assert.equal(length32895.subarray(0, 3).toString("hex").toUpperCase(), "7CFFFF");
  assert.deepEqual(parsed.downlinks.map((downlink) => downlink.length), [127, 128, 129, 32895]);
});

test("parseTlvPayload rejects the old four-byte extended tag encoding", () => {
  const payload = oldFourByteTagTlv(0x8001, Buffer.from([87]));

  assert.throws(
    () => parseTlvPayload(payload),
    /Field 0x8000 declares length 129, which exceeds the remaining payload/
  );
});

test("encodeTlvPayload emits two-byte tag and length headers when needed", () => {
  const longDownlink = Buffer.alloc(130, 0xCD);
  const encoded = encodeTlvPayload({
    version: 89,
    downlinks: [longDownlink]
  }, { direction: "downlink" });

  const expected = Buffer.concat([
    tlv(0x01, Buffer.from("0059", "hex")),
    tlv(0x7C, longDownlink)
  ]).toString("hex").toUpperCase();

  assert.equal(encoded, expected);
  assert.deepEqual(parseTlvPayload(Buffer.from(encoded, "hex")), {
    version: 89,
    downlinks: [longDownlink]
  });
});

test("encodeTlvPayload emits raw two-byte extended tags", () => {
  const encoded = encodeTlvPayload({ battery: 87 }, { direction: "uplink" });

  assert.equal(encoded, "80010157");
  assert.deepEqual(parseTlvPayload(Buffer.from(encoded, "hex")), { battery: 87 });
});

test("encodeTlvPayload emits extended length headers using the 0x8000 to 128 offset", () => {
  const encoded128 = encodeTlvPayload({
    downlinks: [Buffer.alloc(128, 0x80)]
  }, { direction: "downlink" });
  const encoded129 = encodeTlvPayload({
    downlinks: [Buffer.alloc(129, 0x81)]
  }, { direction: "downlink" });
  const encoded32895 = encodeTlvPayload({
    downlinks: [Buffer.alloc(32895, 0xFF)]
  }, { direction: "downlink" });

  assert.equal(encoded128.slice(0, 6), "7C8000");
  assert.equal(encoded129.slice(0, 6), "7C8001");
  assert.equal(encoded32895.slice(0, 6), "7CFFFF");
  assert.equal(parseTlvPayload(Buffer.from(encoded32895, "hex")).downlinks[0].length, 32895);
});

test("encodeTlvPayload accepts hex strings for buffer fields", () => {
  const encoded = encodeTlvPayload({
    version: 2,
    signature: "00112233445566778899AABBCCDDEEFF"
  }, { direction: "uplink" });

  const parsed = parseTlvPayload(Buffer.from(encoded, "hex"));

  assert.equal(parsed.version, 2);
  assert.deepEqual(
    parsed.signature,
    Buffer.from("00112233445566778899AABBCCDDEEFF", "hex")
  );
});




test("encodeTlvPayload can encode the default message from the documentation", () => {
  const encoded = encodeTlvPayload({
    version: 1,
    isConfirmed: true,
    stid: Buffer.from("00001111", "hex"),
    fCntUp: 12345,
    payload: "010c00" // Simple button press
  }, { direction: "uplink" });

  assert.equal(
      encoded,
      "010200010201017E03010C001A0400001111100400003039"
  );
});
