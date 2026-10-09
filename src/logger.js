const LEVELS = ["error", "warn", "info", "debug", "trace"];

function serializeForLog(value) {
  if (Buffer.isBuffer(value)) {
    return value.toString("hex").toUpperCase();
  }

  if (Array.isArray(value)) {
    return value.map((entry) => serializeForLog(entry));
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, serializeForLog(entry)])
    );
  }

  return value;
}

function createLogger({ level = "info", includePayloads = false } = {}) {
  const threshold = LEVELS.indexOf(level);

  function canLog(messageLevel) {
    const messageIndex = LEVELS.indexOf(messageLevel);
    return messageIndex !== -1 && messageIndex <= threshold;
  }

  function write(messageLevel, message, context = {}) {
    if (!canLog(messageLevel)) {
      return;
    }

    const safeContext = serializeForLog(context);
    if (!includePayloads && safeContext.payload !== undefined) {
      safeContext.payload = "[redacted]";
    }

    const line = {
      ts: new Date().toISOString(),
      level: messageLevel,
      message,
      ...safeContext
    };

    process.stdout.write(`${JSON.stringify(line)}\n`);
  }

  return {
    error(message, context) {
      write("error", message, context);
    },
    warn(message, context) {
      write("warn", message, context);
    },
    info(message, context) {
      write("info", message, context);
    },
    debug(message, context) {
      write("debug", message, context);
    },
    trace(message, context) {
      write("trace", message, context);
    }
  };
}

module.exports = {
  createLogger,
  serializeForLog
};
