const { postJson } = require("../httpClient");

function buildDownlinkUrl(apiUrl, path) {
  if (!apiUrl) {
    return "";
  }

  const baseUrl = apiUrl.endsWith("/") ? apiUrl : `${apiUrl}/`;
  return new URL(path, baseUrl).toString();
}

function hasOwn(value, key) {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function assertRequiredCounter(entry, counterField, counter) {
  if (!entry || typeof entry !== "object" || Buffer.isBuffer(entry) || ArrayBuffer.isView(entry)) {
    throw new Error(`Downlink service response must include "${counterField}"`);
  }

  if (!hasOwn(entry, counterField) || counter === null || counter === undefined) {
    throw new Error(`Downlink service response must include "${counterField}"`);
  }
}

function assertRequiredCreatedAt(entry, createdAtField, createdAt) {
  if (!entry || typeof entry !== "object" || Buffer.isBuffer(entry) || ArrayBuffer.isView(entry)) {
    throw new Error(`Downlink service response must include "${createdAtField}"`);
  }

  if (!hasOwn(entry, createdAtField) || createdAt === null || createdAt === undefined) {
    throw new Error(`Downlink service response must include "${createdAtField}"`);
  }
}

function compareNullableValues(left, right) {
  if (left === right) {
    return 0;
  }
  if (left === null || left === undefined) {
    return 1;
  }
  if (right === null || right === undefined) {
    return -1;
  }
  return left < right ? -1 : 1;
}

function normalizeRetransmitReconciliation(response, requestedRetransmits) {
  if (!response || typeof response !== "object" || !Array.isArray(response.retransmits)) {
    throw new TypeError('Downlink retransmit reconciliation response must include a "retransmits" array');
  }

  const requestedCounters = new Set(requestedRetransmits.map((retransmit) => retransmit.counter));
  const decisionsByCounter = new Map();

  for (const decision of response.retransmits) {
    if (!decision || typeof decision !== "object" || !Number.isInteger(decision.counter)) {
      throw new TypeError('Downlink retransmit reconciliation decisions must include an integer "counter"');
    }
    if (decision.action !== "continue" && decision.action !== "cancel") {
      throw new TypeError('Downlink retransmit reconciliation decisions must use "continue" or "cancel"');
    }
    if (!requestedCounters.has(decision.counter) || decisionsByCounter.has(decision.counter)) {
      throw new TypeError("Downlink retransmit reconciliation response does not match the request");
    }
    decisionsByCounter.set(decision.counter, {
      counter: decision.counter,
      action: decision.action,
      ...(typeof decision.reason === "string" ? { reason: decision.reason } : {})
    });
  }

  if (decisionsByCounter.size !== requestedCounters.size) {
    throw new TypeError("Downlink retransmit reconciliation response must decide every requested retransmit");
  }

  return requestedRetransmits.map((retransmit) => decisionsByCounter.get(retransmit.counter));
}

class DownlinkService {
  constructor(config, { authService } = {}) {
    this.config = {
      idField: "id",
      itemPayloadField: "payload",
      counterField: "counter",
      createdAtField: "createdAt",
      ...config
    };
    this.authService = authService;
  }

  async buildRequestOptions() {
    const options = {
      timeoutMs: this.config.timeoutMs
    };

    if (this.authService) {
      const accessToken = await this.authService.getAccessToken();
      options.authHeader = "Authorization";
      options.authToken = `Bearer ${accessToken}`;
    }

    return options;
  }

  normalizePendingDownlink(entry) {
    const idField = this.config.idField;
    const itemPayloadField = this.config.itemPayloadField;
    const counterField = this.config.counterField;
    const createdAtField = this.config.createdAtField;
    const id = hasOwn(entry, idField) ? entry[idField] : null;
    const counter = hasOwn(entry, counterField) ? entry[counterField] : null;
    const createdAt = hasOwn(entry, createdAtField) ? entry[createdAtField] : null;

    assertRequiredCounter(entry, counterField, counter);
    assertRequiredCreatedAt(entry, createdAtField, createdAt);

    if (hasOwn(entry, itemPayloadField)) {
      return {
        payload: entry[itemPayloadField],
        id,
        counter,
        createdAt
      };
    }

    const { [idField]: _id, [counterField]: _counter, [createdAtField]: _createdAt, ...payload } = entry;
    return {
      payload,
      id,
      counter,
      createdAt
    };
  }

  sortPendingDownlinks(downlinks) {
    return [...downlinks].sort((left, right) => {
      const createdAtComparison = compareNullableValues(left.createdAt, right.createdAt);
      if (createdAtComparison !== 0) {
        return createdAtComparison;
      }

      return compareNullableValues(left.counter, right.counter);
    });
  }

  normalizePendingDownlinksResponse(response) {
    if (!Array.isArray(response)) {
      throw new TypeError("Downlink service response must be an array");
    }

    return this.sortPendingDownlinks(response.map((entry) => this.normalizePendingDownlink(entry)));
  }

  async getPendingDownlinks(deviceId, metadata = {}) {
    if (!this.config.enabled) {
      return [];
    }

    const response = await postJson(
      buildDownlinkUrl(this.config.apiUrl, "get-pending-downlinks"),
      { deviceId, metadata },
      await this.buildRequestOptions()
    );

    return this.normalizePendingDownlinksResponse(response);
  }

  async confirmAcknowledgedDownlink(deviceId, downlinkAck) {
    if (!this.config.enabled || downlinkAck === null || downlinkAck === undefined) {
      return [];
    }

    const response = await postJson(
      buildDownlinkUrl(this.config.apiUrl, "confirm-pending-downlink"),
      {
        deviceId,
        counter: downlinkAck
      },
      await this.buildRequestOptions()
    );

    return this.normalizePendingDownlinksResponse(response);
  }

  async markDownlinkSent(deviceId, id) {
    if (!this.config.enabled || id === null || id === undefined) {
      return {};
    }

    return postJson(
      buildDownlinkUrl(this.config.apiUrl, "mark-downlink-sent"),
      {
        deviceId,
        downlink: id
      },
      await this.buildRequestOptions()
    );
  }

  async reconcileRetransmits(deviceId, retransmits) {
    if (!this.config.enabled || retransmits.length === 0) {
      return [];
    }

    const response = await postJson(
      buildDownlinkUrl(this.config.apiUrl, "reconcile-downlink-retransmits"),
      { deviceId, retransmits },
      await this.buildRequestOptions()
    );

    return normalizeRetransmitReconciliation(response, retransmits);
  }
}

module.exports = {
  DownlinkService,
  buildDownlinkUrl
};
