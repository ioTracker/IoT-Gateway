const RETRY_INFO_FIELDS = ["fCntUp", "fCntDown", "downlinkAck", "uplinkAck", "retransmitCount"];
const RETRY_EVENT_WIDTH = "downlink_tx".length;
const RETRY_VALUE_WIDTH = 5;

function getRetryInfoValue(source, field) {
  return Object.prototype.hasOwnProperty.call(source, field) ? source[field] : null;
}

function buildRetryInfo(source = {}, overrides = {}) {
  return Object.fromEntries(
    RETRY_INFO_FIELDS.map((field) => [
      field,
      Object.prototype.hasOwnProperty.call(overrides, field)
        ? overrides[field]
        : getRetryInfoValue(source, field)
    ])
  );
}

function formatRetryInfoValue(value) {
  if (value === null || value === undefined) {
    return "".padStart(RETRY_VALUE_WIDTH, " ");
  }

  return String(value).padStart(RETRY_VALUE_WIDTH, " ");
}

function formatRetryEvent(event) {
  return String(event).padEnd(RETRY_EVENT_WIDTH, " ");
}

function buildRetryInfoString(source = {}, overrides = {}) {
  const retryInfo = buildRetryInfo(source, overrides);
  return RETRY_INFO_FIELDS
    .map((field) => `${field}=${formatRetryInfoValue(retryInfo[field])}`)
    .join(" ");
}

module.exports = {
  buildRetryInfo,
  buildRetryInfoString,
  formatRetryEvent
};
