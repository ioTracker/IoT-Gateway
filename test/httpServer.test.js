const test = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("events");
const { createRequestListener } = require("../src/transports/httpServer");

function createResponse() {
  let resolveEnded;
  const ended = new Promise((resolve) => {
    resolveEnded = resolve;
  });

  return {
    statusCode: null,
    headers: null,
    body: null,
    writableEnded: false,
    ended,
    writeHead(statusCode, headers) {
      this.statusCode = statusCode;
      this.headers = headers;
    },
    end(body) {
      this.body = body;
      this.writableEnded = true;
      resolveEnded();
    }
  };
}

test("http server exposes readiness status with application version", async () => {
  const logger = {
    info() {},
    error() {}
  };
  const handler = {
    async handle() {
      throw new Error("handle should not be called for /status");
    }
  };

  const requestListener = createRequestListener({
    config: {
      host: "127.0.0.1",
      port: 0,
      uplinkPath: "/uplink"
    },
    handler,
    logger,
    version: "1.0.0-test"
  });

  const req = new EventEmitter();
  req.method = "GET";
  req.url = "/status";

  const response = {
    statusCode: null,
    headers: null,
    body: null,
    writableEnded: false,
    writeHead(statusCode, headers) {
      this.statusCode = statusCode;
      this.headers = headers;
    },
    end(body) {
      this.body = body;
      this.writableEnded = true;
    }
  };

  await requestListener(req, response);

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.headers, { "content-type": "application/json" });
  assert.deepEqual(JSON.parse(response.body), {
    status: "ok",
    version: "1.0.0-test"
  });
});

test("http server returns device keys in development mode", async () => {
  const logger = {
    info() {},
    error() {}
  };
  const handler = {
    async handle() {
      throw new Error("handle should not be called for /keys");
    }
  };
  const keyProvider = {
    async getKey(deviceId) {
      assert.equal(deviceId, "00001111");
      return "test-device-key";
    }
  };

  const requestListener = createRequestListener({
    config: {
      host: "127.0.0.1",
      port: 0,
      uplinkPath: "/uplink"
    },
    env: "development",
    handler,
    keyProvider,
    logger,
    version: "1.0.0-test"
  });

  const req = new EventEmitter();
  req.method = "GET";
  req.url = "/keys/00001111";
  const response = createResponse();

  await requestListener(req, response);

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.headers, { "content-type": "application/json" });
  assert.deepEqual(JSON.parse(response.body), {
    deviceId: "00001111",
    key: "test-device-key"
  });
});

test("http server logs device keys without returning them in production mode", async () => {
  const infoLogs = [];
  const logger = {
    info(message, context) {
      infoLogs.push({ message, context });
    },
    error() {}
  };
  const handler = {
    async handle() {
      throw new Error("handle should not be called for /keys");
    }
  };
  const keyProvider = {
    async getKey(deviceId) {
      assert.equal(deviceId, "00001111");
      return "test-device-key";
    }
  };

  const requestListener = createRequestListener({
    config: {
      host: "127.0.0.1",
      port: 0,
      uplinkPath: "/uplink"
    },
    env: "production",
    handler,
    keyProvider,
    logger,
    version: "1.0.0-test"
  });

  const req = new EventEmitter();
  req.method = "GET";
  req.url = "/keys/00001111";
  const response = createResponse();

  await requestListener(req, response);

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.headers, { "content-type": "application/json" });
  assert.deepEqual(JSON.parse(response.body), {
    deviceId: "00001111"
  });
  assert.deepEqual(infoLogs, [
    {
      message: "Device key loaded",
      context: {
        deviceId: "00001111",
        key: "test-device-key"
      }
    }
  ]);
});

test("http server returns the downlink ACK payload as plain hex", async () => {
  const logger = {
    info() {},
    error() {}
  };
  const downlink = Buffer.from("90020163", "hex");
  const handler = {
    async handle(rawBody, context) {
      await context.sendDownlink(downlink);
      return {
        deviceId: "00001111",
        pendingChange: false
      };
    }
  };

  const requestListener = createRequestListener({
    config: {
      host: "127.0.0.1",
      port: 0,
      uplinkPath: "/uplink"
    },
    handler,
    logger,
    version: "1.0.0-test"
  });

  const req = new EventEmitter();
  req.method = "POST";
  req.url = "/uplink";

  const response = {
    statusCode: null,
    headers: null,
    body: null,
    writableEnded: false,
    writeHead(statusCode, headers) {
      this.statusCode = statusCode;
      this.headers = headers;
    },
    end(body) {
      this.body = body;
      this.writableEnded = true;
    }
  };

  const completion = requestListener(req, response);
  req.emit("data", Buffer.from("010101", "utf8"));
  req.emit("end");
  await completion;

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.headers, { "content-type": "text/plain; charset=utf-8" });
  assert.equal(response.body, "90020163");
});

test("http server exposes debug endpoint in development mode", async () => {
  const logger = {
    info() {},
    error() {}
  };
  const handler = {
    async debug(rawBody, context) {
      assert.equal(rawBody, "010101");
      assert.equal(context.transport, "http");
      assert.equal(context.direction, "uplink");
      return {
        deviceId: "00001111",
        parsedPayload: {
          version: 1,
          stid: "00001111"
        },
        debug: {
          encryption: {
            encrypted: false
          }
        }
      };
    },
    async handle() {
      throw new Error("handle should not be called for /debug");
    }
  };

  const requestListener = createRequestListener({
    config: {
      host: "127.0.0.1",
      port: 0,
      uplinkPath: "/uplink"
    },
    env: "development",
    handler,
    logger,
    version: "1.0.0-test"
  });

  const req = new EventEmitter();
  req.method = "POST";
  req.url = "/debug";
  const response = createResponse();

  await requestListener(req, response);
  req.emit("data", Buffer.from("010101", "utf8"));
  req.emit("end");
  await response.ended;

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.headers, { "content-type": "application/json" });
  assert.deepEqual(JSON.parse(response.body), {
    deviceId: "00001111",
    parsedPayload: {
      version: 1,
      stid: "00001111"
    },
    debug: {
      encryption: {
        encrypted: false
      }
    }
  });
});

test("http server does not expose debug endpoint in production mode", async () => {
  const logger = {
    info() {},
    error() {}
  };
  const handler = {
    async debug() {
      throw new Error("debug should not be called in production");
    },
    async handle() {
      throw new Error("handle should not be called for /debug");
    }
  };

  const requestListener = createRequestListener({
    config: {
      host: "127.0.0.1",
      port: 0,
      uplinkPath: "/uplink"
    },
    env: "production",
    handler,
    logger,
    version: "1.0.0-test"
  });

  const req = new EventEmitter();
  req.method = "POST";
  req.url = "/debug";
  const response = createResponse();

  await requestListener(req, response);

  assert.equal(response.statusCode, 404);
  assert.deepEqual(response.headers, { "content-type": "application/json" });
  assert.deepEqual(JSON.parse(response.body), {
    error: "Not found"
  });
});

test("http server only exposes debug endpoint in development mode", async () => {
  const logger = {
    info() {},
    error() {}
  };
  const handler = {
    async debug() {
      throw new Error("debug should not be called outside development");
    }
  };

  const requestListener = createRequestListener({
    config: {
      host: "127.0.0.1",
      port: 0,
      uplinkPath: "/uplink"
    },
    env: "test",
    handler,
    logger,
    version: "1.0.0-test"
  });

  const req = new EventEmitter();
  req.method = "POST";
  req.url = "/debug";
  const response = createResponse();

  await requestListener(req, response);

  assert.equal(response.statusCode, 404);
  assert.deepEqual(JSON.parse(response.body), {
    error: "Not found"
  });
});

test("http server returns 502 when an upstream HTTP dependency fails", async () => {
  const logger = {
    info() {},
    error() {}
  };
  const handler = {
    async handle() {
      const error = new Error("Request to https://example.test/forward failed with status 500");
      error.code = "HTTP_RESPONSE_ERROR";
      error.statusCode = 500;
      throw error;
    }
  };

  const requestListener = createRequestListener({
    config: {
      host: "127.0.0.1",
      port: 0,
      uplinkPath: "/uplink"
    },
    handler,
    logger,
    version: "1.0.0-test"
  });

  const req = new EventEmitter();
  req.method = "POST";
  req.url = "/uplink";
  const response = createResponse();

  await requestListener(req, response);
  req.emit("data", Buffer.from("010101", "utf8"));
  req.emit("end");
  await response.ended;

  assert.equal(response.statusCode, 502);
  assert.deepEqual(JSON.parse(response.body), {
    error: "Request to https://example.test/forward failed with status 500"
  });
});

test("http server keeps malformed uplinks as 400", async () => {
  const logger = {
    info() {},
    error() {}
  };
  const handler = {
    async handle() {
      throw new Error("Incoming TLV payload must be a Buffer, Uint8Array, ArrayBuffer, or even-length hexadecimal string");
    }
  };

  const requestListener = createRequestListener({
    config: {
      host: "127.0.0.1",
      port: 0,
      uplinkPath: "/uplink"
    },
    handler,
    logger,
    version: "1.0.0-test"
  });

  const req = new EventEmitter();
  req.method = "POST";
  req.url = "/uplink";
  const response = createResponse();

  await requestListener(req, response);
  req.emit("data", Buffer.from("not-tlv", "utf8"));
  req.emit("end");
  await response.ended;

  assert.equal(response.statusCode, 400);
  assert.deepEqual(JSON.parse(response.body), {
    error: "Incoming TLV payload must be a Buffer, Uint8Array, ArrayBuffer, or even-length hexadecimal string"
  });
});
