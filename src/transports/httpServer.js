const http = require("http");
const { serializeError } = require("../httpClient");

const SERVER_ERROR_CODES = new Set([
  "HTTP_REQUEST_FAILED",
  "HTTP_REQUEST_TIMEOUT",
  "HTTP_RESPONSE_ERROR"
]);

function getUplinkErrorStatus(error) {
  return SERVER_ERROR_CODES.has(error.code) ? 502 : 400;
}

function getKeyErrorStatus(error) {
  return SERVER_ERROR_CODES.has(error.code) ? 502 : 500;
}

function getKeyDeviceId(url) {
  if (!url) return null;
  const match = url.pathname.match(/^\/keys\/([^/]+)$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function createRequestListener({ config, env = "development", handler, keyProvider, logger, version }) {
  return async (req, res) => {
    if (req.method === "GET" && req.url === "/status") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        status: "ok",
        version
      }));
      return;
    }

    const url = req.method === "GET" ? new URL(req.url, "http://localhost") : null;
    if (url?.pathname === "/healthz") {
      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      res.end(JSON.stringify({ status: "ok" }));
      return;
    }

    if (url?.pathname === "/healthz/uplink") {
      const headers = { "content-type": "application/json", "cache-control": "no-store" };
      const minuteValues = url.searchParams.getAll("minutes");
      const minuteValue = minuteValues[0] ?? "5";
      const minutes = Number(minuteValue);
      if (minuteValues.length > 1 || !/^\d+$/.test(minuteValue) || !Number.isSafeInteger(minutes) || minutes <= 0) {
        res.writeHead(400, headers);
        res.end(JSON.stringify({ error: "minutes must be a positive integer" }));
        return;
      }

      const lastUplinkAt = handler.lastUplinkAt;
      const recent = lastUplinkAt != null && (Date.now() - lastUplinkAt) / 60000 <= minutes;
      res.writeHead(recent ? 200 : 503, headers);
      res.end(JSON.stringify({
        lastUplinkAt: lastUplinkAt == null ? null : new Date(lastUplinkAt).toISOString()
      }));
      return;
    }

    const keyDeviceId = getKeyDeviceId(url);
    if (keyDeviceId) {
      try {
        const key = await keyProvider.getKey(keyDeviceId);

        if (env === "production") {
          logger.info("Device key loaded", {
            deviceId: keyDeviceId,
            key
          });
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ deviceId: keyDeviceId }));
          return;
        }

        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({
          deviceId: keyDeviceId,
          key
        }));
      } catch (error) {
        logger.error("HTTP key loading failed", {
          deviceId: keyDeviceId,
          error: error.message,
          code: error.code,
          errorDetails: serializeError(error)
        });
        res.writeHead(getKeyErrorStatus(error), { "content-type": "application/json" });
        res.end(JSON.stringify({ error: error.message }));
      }
      return;
    }

    const isDebugRequest = req.method === "POST" && req.url === "/debug";
    const isUplinkRequest = req.method === "POST" && req.url === config.uplinkPath;

    if (isDebugRequest && env !== "development") {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "Not found" }));
      return;
    }

    if (!isUplinkRequest && !isDebugRequest) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "Not found" }));
      return;
    }

    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", async () => {
      const receivedAt = Date.now();
      const rawBody = Buffer.concat(chunks).toString("utf8");

      try {
        if (isDebugRequest) {
          const result = await handler.debug(rawBody, {
            transport: "http",
            direction: "uplink",
            receivedAt
          });

          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(result));
          return;
        }

        const result = await handler.handle(rawBody, {
          transport: "http",
          direction: "uplink",
          receivedAt,
          supportsRetransmit: false,
          sendDownlink: async (payload) => {
            if (res.writableEnded) {
              return;
            }
            res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
            res.end(payload.toString("hex").toUpperCase());
          }
        });

        if (!res.writableEnded) {
          res.writeHead(202, { "content-type": "application/json" });
          res.end(JSON.stringify({
            status: "accepted",
            deviceId: result.deviceId
          }));
        }
      } catch (error) {
        logger.error("HTTP uplink handling failed", {
          error: error.message,
          code: error.code,
          errorDetails: serializeError(error)
        });
        if (!res.writableEnded) {
          res.writeHead(getUplinkErrorStatus(error), { "content-type": "application/json" });
          res.end(JSON.stringify({ error: error.message }));
        }
      }
    });
  };
}

function createHttpServer({ config, env, handler, keyProvider, logger, version }) {
  const server = http.createServer(createRequestListener({ config, env, handler, keyProvider, logger, version }));

  return {
    start() {
      return new Promise((resolve) => {
        server.listen(config.port, config.host, () => {
          logger.info("HTTP server listening", { host: config.host, port: config.port, path: config.uplinkPath });
          resolve(server);
        });
      });
    },
    stop() {
      return new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }
  };
}

module.exports = {
  createHttpServer,
  createRequestListener,
  getKeyErrorStatus,
  getUplinkErrorStatus
};
