const test = require("node:test");
const assert = require("node:assert/strict");

const { Forwarder } = require("../src/services/forwarder");

test("forwarder skips forwarding when no URL is configured", async () => {
  const forwarder = new Forwarder({
    url: "",
    timeoutMs: 1,
    authHeader: "",
    authToken: ""
  });

  const result = await forwarder.forward({ deviceId: "00001111" });

  assert.equal(result, undefined);
});
