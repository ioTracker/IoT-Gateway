# Changelog

## v1.1.0

### Added

- New backend API call: `POST {DOWNLINK_API_URL}/mark-downlink-failed`. After the retry limit is reached and the final ACK window expires, the gateway reports `deviceId`, `downlink`, `counter`, `reason: "retry_limit_reached"`, and `retriesSent`. Failed notifications are retried without resending the command. See the [Mark Downlink Failed API contract in the integrator guide](integrator-guide.md#mark-downlink-failed) for the request format and backend requirements.

### Fixed

- Repeated pending responses for the same downlink no longer reset its retry counter or timer. Acknowledged, cancelled, and exhausted items remain blocked for the lifetime of the gateway process. Retry counters start over after a restart.
