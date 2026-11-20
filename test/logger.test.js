const test = require("node:test");
const assert = require("node:assert/strict");
const { serializeForLog, createLogger } = require("../src/logger");

test("serializeForLog renders buffers as uppercase hex recursively", () => {
  const serialized = serializeForLog({
    payload: Buffer.from("010C00", "hex"),
    nested: {
      stid: Buffer.from("00001111", "hex")
    },
    list: [Buffer.from("ABCD", "hex")]
  });

  assert.deepEqual(serialized, {
    payload: "010C00",
    nested: {
      stid: "00001111"
    },
    list: ["ABCD"]
  });
});

test("createLogger writes debug raw payload as hex", () => {
  const originalWrite = process.stdout.write;
  const writes = [];

  process.stdout.write = (chunk) => {
    writes.push(chunk);
    return true;
  };

  try {
    const logger = createLogger({ level: "debug" });
    logger.debug("Uplink received", {
      transport: "udp",
      rawPayload: Buffer.from("01010102046610524E7F03010C001A0400001111", "hex")
    });
  } finally {
    process.stdout.write = originalWrite;
  }

  assert.equal(writes.length, 1);
  const line = JSON.parse(writes[0]);
  assert.equal(line.message, "Uplink received");
  assert.equal(line.transport, "udp");
  assert.equal(line.rawPayload, "01010102046610524E7F03010C001A0400001111");
});
