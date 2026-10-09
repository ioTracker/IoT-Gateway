# IoT Uplink Gateway

Also referred to as the ioThings Middleware Server in [integrator-guide.md](integrator-guide.md#high-level-communication-sequence).

Node.js service that accepts IoT uplinks over HTTP and UDP, decrypts them using a device-specific key, forwards the decrypted payload to another HTTP(S) service, and sends a TLV downlink ACK back to the device only when the uplink opens a receive window with `0x02` (`isConfirmed`), with an optional queued downlink payload.

Inbound device HTTP is plain HTTP (no built-in TLS). Terminate TLS in front of the service if you need HTTPS.

## What it does

- Listens for uplinks on HTTP and/or UDP.
- Parses the uplink message and extracts the device identifier before forwarding.
- Fetches the encryption key from either:
  - a database table (`postgres`, `mysql`, or `mssql`)
  - an external HTTP(S) key service
- Decrypts the message in a dedicated parser module so the format can evolve independently.
- Forwards the decrypted payload with `POST` to another HTTP(S) endpoint.
- Sends a TLV downlink ACK using `0x14` (`uplinkAck`) only when the uplink includes `fCntUp` and `0x02` (`isConfirmed`) is true; ACKs for encrypted uplinks are encrypted with the same AES-GCM TLV envelope. If `isConfirmed` is absent or false, no ACK is sent.
- Optionally checks for pending downlinks when `isConfirmed` is true and, if so, sends them one at a time as a `0x7C` downlink field.
- Marks pending downlink IDs as sent after the downlink has been sent to the device.

## Message shape

The parser is isolated in [src/parser.js](src/parser.js). Uplinks must be TLV messages. The full message is parsed first. If tag `0x7F` (`encryptedMessage`) is present, only that field is AES-GCM decrypted using the IV from tag `0x21` and AES-256 PSK crypto mode from tag `0x22`, and the decrypted TLVs are merged back into the parsed uplink object. Encrypted downlink ACKs put the TLV-encoded ACK inside `encryptedMessage`; plaintext fields such as `version` and `stid` are used as AES-GCM AAD. See [crypto.md](crypto.md) for the encryption format, AAD construction, and example payloads.

The TLV spec in [tlv-tag-spec.json](tlv-tag-spec.json) is intentionally permissive. A generated Markdown version is available in [tlv-tag-spec.md](tlv-tag-spec.md). Direction-related columns are kept as descriptive metadata and are not enforced by the parser.

Integrator-facing HTTP request and response shapes are documented in [integrator-guide.md](integrator-guide.md).

If your uplink format changes, adjust only the parser module and keep the rest of the system unchanged.

## Configuration

All runtime configuration lives in environment variables. Start from [.env.example](.env.example).

### Core

- `HTTP_ENABLED`, `HTTP_HOST`, `HTTP_PORT`, `HTTP_UPLINK_PATH`
- `UDP_ENABLED`, `UDP_HOST`, `UDP_PORT`, `UDP_TYPE`
- `ENCRYPTION_ALGORITHM=aes-256-gcm`
- `ENCRYPTION_ALLOWED_CLOCK_SKEW_SECONDS=60`

At startup, the server logs warnings for potentially risky configuration, including
non-default encryption settings, payload logging, crypto logging, and production endpoints that use
unencrypted HTTP. These warnings do not prevent the server from starting.

### Logging

- `LOG_LEVEL=error|warn|info|debug|trace`
- `LOG_INCLUDE_PAYLOADS=true|false`
- `LOG_INCLUDE_CRYPTO=true|false` - logs encryption keys, IVs, signatures, AAD, and ciphertext for encrypted uplinks and downlinks when enabled.
- `LOG_RETRY_INFO=true|false` - logs compact retry counters for each received uplink and sent downlink: `fCntUp`, `fCntDown`, `downlinkAck`, `uplinkAck`, and `retransmitCount`.

### Key lookup

- `KEY_PROVIDER=HTTP|DB`

Encryption keys returned by the HTTP provider or read from the database must be hexadecimal strings.
Loaded keys are cached in memory by device id for the lifetime of the server process. Restart the server after changing a device key.

For HTTP:

- `KEY_HTTP_URL`
- `KEY_HTTP_METHOD`
- `KEY_HTTP_TIMEOUT_MS`
- `KEY_HTTP_AUTH_HEADER`
- `KEY_HTTP_AUTH_TOKEN`
- `KEY_HTTP_USE_DOWNLINK_TOKEN`
- `KEY_HTTP_DEVICE_ID_FIELD`
- `KEY_HTTP_RESPONSE_KEY_FIELD`

Set `KEY_HTTP_USE_DOWNLINK_TOKEN=true` to send the shared OAuth token as `Authorization: Bearer <access_token>` on HTTP key lookup requests. When enabled, the downlink OAuth settings are required and override `KEY_HTTP_AUTH_HEADER` and `KEY_HTTP_AUTH_TOKEN` for key lookup requests.

For DB:

- `KEY_DB_CLIENT=postgres|mysql|mssql`
- `KEY_DB_CONNECTION_STRING`
- `KEY_DB_TABLE`
- `KEY_DB_DEVICE_ID_COLUMN`
- `KEY_DB_KEY_COLUMN`

### Forwarding

- `FORWARD_URL` - required in production; leave empty outside production to disable forwarding
- `FORWARD_TIMEOUT_MS`
- `FORWARD_AUTH_HEADER`
- `FORWARD_AUTH_TOKEN`

### Optional pending downlinks

- `DOWNLINK_CHECK_ENABLED=true|false`
- `DOWNLINK_API_URL` - base URL for the downlink API, for example `http://api.iotracker.test/lte-connector`
- `DOWNLINK_CHECK_TIMEOUT_MS`
- `DOWNLINK_TOKEN_ENDPOINT`
- `DOWNLINK_CLIENT_ID`
- `DOWNLINK_CLIENT_SECRET`
- `DOWNLINK_UUID_FIELD`
- `DOWNLINK_ITEM_PAYLOAD_FIELD`
- `DOWNLINK_COUNTER_FIELD`
- `DOWNLINK_CREATED_AT_FIELD`
- `DOWNLINK_RETRANSMIT_WINDOW_MS` - milliseconds to wait for a matching `downlinkAck` before retransmitting a downlink with `fCntDown`; `0` disables retransmit
- `DOWNLINK_RETRANSMIT_MAX_RETRIES` - maximum number of retransmit attempts after the initial send; `0` disables retransmit
- `DOWNLINK_RETRANSMIT_RECONCILE_INTERVAL_MS` - minimum interval between backend reconciliation checks for an active UDP retransmit; defaults to `60000`, and `0` disables reconciliation

When downlink checks are enabled, `DOWNLINK_TOKEN_ENDPOINT`, `DOWNLINK_CLIENT_ID`, and `DOWNLINK_CLIENT_SECRET` are required. Startup creates an OAuth2 client credentials token service, loads an access token before transports start, requires `access_token` and positive numeric `expires_in` fields in the token response, and refreshes the token before expiration. Downlink API requests send the current token as `Authorization: Bearer <access_token>`.

When enabled, the downlink service is queried only for uplinks where `0x02` (`isConfirmed`) is true and no queued downlink is already held locally for that device. Its response is an array of queued downlinks, which may be empty. Entries are handled ordered by `createdAt` first and then `counter`. A queued downlink response must include `createdAt` and `counter`; the default shape is `{ "id": "...", "createdAt": "2024-04-05T11:00:00.000Z", "counter": 235, "payload": "..." }`. The `payload` value is sent as the single `0x7C` field, `counter` is sent as `fCntDown`, and the ID is marked sent after send.

When retransmit is enabled, the server tracks sent downlinks that include `fCntDown` on transports that can send asynchronously, such as UDP. If a later uplink does not include `downlinkAck` for that counter before `DOWNLINK_RETRANSMIT_WINDOW_MS` elapses, the exact same formatted downlink bytes are sent again until `DOWNLINK_RETRANSMIT_MAX_RETRIES` is reached. Retry sends include `isRetry: true` and `retryAttempt` in the `Downlink sent` log.

Before a retry after `DOWNLINK_RETRANSMIT_RECONCILE_INTERVAL_MS` has elapsed, the server calls `reconcile-downlink-retransmits`. The backend must return a decision for the active `fCntDown`: `continue` preserves retransmission and `cancel` immediately removes the local retry timer. A failed reconciliation is logged and fails open: the retry remains active. This endpoint is deliberately separate from `get-pending-downlinks`, because a sent downlink may no longer be in the pending queue while it is still awaiting acknowledgement.

When enabled, the service posts to these endpoints relative to `DOWNLINK_API_URL`:

- `get-pending-downlinks` to fetch the queued downlink array.
- `confirm-pending-downlink` to confirm an incoming `0x13` (`downlinkAck`) and receive the updated queued downlink array.
- `mark-downlink-sent` after a queued downlink has been sent; its response does not update the local queue.
- `reconcile-downlink-retransmits` to decide whether an already-sent UDP downlink should continue retrying or be cancelled.

When an incoming uplink contains `0x13` (`downlinkAck`), the service posts the ACK to `confirm-pending-downlink` asynchronously:

```json
{
  "deviceId": "00001111",
  "counter": 235
}
```

That ACK-confirm response is interpreted as the updated queued downlink array and replaces the local queue for the device.

After a downlink send succeeds, the service asynchronously posts the following body to `mark-downlink-sent`:

```json
{
  "deviceId": "00001111",
  "downlink": "downlink-id"
}
```

The `mark-downlink-sent` response body is ignored after any successful 2xx response.

The legacy `CONFIG_*` variables are still accepted as fallbacks for enabled, timeout, and auth settings.

## Running locally

1. Install dependencies:

```bash
npm install
```

2. Create your environment file:

```bash
cp .env.example .env
```

3. Start the service:

```bash
npm start
```

HTTP uplinks will be accepted on `POST /uplink` by default, and UDP uplinks on port `5000`. HTTP responses return the downlink payload as an uppercase hex string.

When `NODE_ENV=development`, `POST /debug` accepts the same payload as `/uplink` and returns the parsed payload plus key and encryption diagnostics. The debug endpoint is not exposed outside development mode.

## Docker

Build:

```bash
docker build -t iot-uplink-gateway .
```

Run:

```bash
docker run --env-file .env -p 8080:8080 -p 5000:5000/udp iot-uplink-gateway
```

## Testing

Run:

```bash
npm test
```

The test suite covers the parsing/decryption path, HTTP key lookup, forwarding, TLV ACK generation, and optional queued downlink payloads.
