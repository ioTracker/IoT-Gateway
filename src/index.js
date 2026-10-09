const { config, validateConfig, getConfigWarnings } = require("./config");
const { createLogger } = require("./logger");
const { createKeyProvider } = require("./services/keyProvider");
const { Forwarder } = require("./services/forwarder");
const { DownlinkService } = require("./services/downlinkService");
const { DownlinkDispatcher } = require("./services/downlinkDispatcher");
const { OAuthClientCredentialsService } = require("./services/oauthClient");
const parser = require("./parser");
const { UplinkHandler } = require("./uplinkHandler");
const { createHttpServer } = require("./transports/httpServer");
const { createUdpServer } = require("./transports/udpServer");
const { version } = require("../package.json");

async function main() {
  validateConfig(config);

  const logger = createLogger(config.logging);

  for (const warning of getConfigWarnings(config)) {
    logger.warn("Potentially risky server configuration", warning);
  }

  let downlinkAuthService = null;

  if (config.downlink.tokenEndpoint) {
    downlinkAuthService = new OAuthClientCredentialsService({
      tokenEndpoint: config.downlink.tokenEndpoint,
      clientId: config.downlink.clientId,
      clientSecret: config.downlink.clientSecret,
      timeoutMs: config.downlink.timeoutMs
    }, {
      logger
    });
    await downlinkAuthService.start();
  }

  const keyProvider = createKeyProvider(config.keyProvider, {
    authService: downlinkAuthService
  });
  const forwarder = new Forwarder(config.forward);
  const downlinkService = new DownlinkService(config.downlink, {
    authService: downlinkAuthService
  });
  const downlinkDispatcher = new DownlinkDispatcher({
    logger,
    parser,
    includeCrypto: config.logging.includeCrypto,
    includeRetryInfo: config.logging.includeRetryInfo
  });
  const handler = new UplinkHandler({
    config,
    keyProvider,
    forwarder,
    downlinkService,
    downlinkDispatcher,
    logger
  });

  const servers = [];

  if (config.transport.http.enabled) {
    const httpServer = createHttpServer({
      config: config.transport.http,
      env: config.env,
      handler,
      keyProvider,
      logger,
      version
    });
    await httpServer.start();
    servers.push(httpServer);
  }

  if (config.transport.udp.enabled) {
    const udpServer = createUdpServer({
      config: config.transport.udp,
      handler,
      logger
    });
    await udpServer.start();
    servers.push(udpServer);
  }

  async function shutdown() {
    logger.info("Shutting down");
    downlinkAuthService?.stop();
    await Promise.all(servers.map((server) => server.stop()));
    process.exit(0);
  }

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((error) => {
  process.stderr.write(`${error.stack}\n`);
  process.exit(1);
});
