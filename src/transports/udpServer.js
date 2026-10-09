const dgram = require("dgram");

function createUdpServer({ config, handler, logger }) {
  const socket = dgram.createSocket(config.type);

  socket.on("message", async (msg, rinfo) => {
    const receivedAt = Date.now();

    try {
      await handler.handle(msg, {
        transport: "udp",
        receivedAt,
        remote: rinfo,
        supportsRetransmit: true,
        sendDownlink: async (payload) => {
          await new Promise((resolve, reject) => {
            socket.send(payload, rinfo.port, rinfo.address, (error) => {
              if (error) {
                reject(error);
                return;
              }
              resolve();
            });
          });
        }
      });
    } catch (error) {
      logger.error("UDP uplink handling failed", {
        error: error.message,
        remoteAddress: rinfo.address,
        remotePort: rinfo.port
      });
    }
  });

  return {
    start() {
      return new Promise((resolve) => {
        socket.bind(config.port, config.host, () => {
          logger.info("UDP server listening", { host: config.host, port: config.port, type: config.type });
          resolve(socket);
        });
      });
    },
    stop() {
      return new Promise((resolve) => {
        socket.close(() => resolve());
      });
    }
  };
}

module.exports = {
  createUdpServer
};
