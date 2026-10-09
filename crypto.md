# Encryption

Encrypted uplinks and encrypted downlink ACKs use AES-256-GCM with a pre-shared key. The TLV message remains partially plaintext so the gateway and device can identify the message and validate the cryptographic mode before decrypting the encrypted payload.

## Encrypted Uplink Shape

The encrypted payload is carried in tag `0x7F` (`encryptedMessage`). The AES-GCM auth tag is carried separately in tag `0x23` (`signature`). All other TLV fields in the same message are plaintext and are used as AES-GCM additional authenticated data.

Required plaintext fields for encrypted uplinks:

| Tag | Field | Purpose |
| --- | --- | --- |
| `0x1A`, `0x1B`, or device identifier equivalent | `stid`, `imei`, or `deviceId` | Identifies the device and key lookup target |
| `0x21` | `iv` | 96-bit AES-GCM IV |
| `0x22` | `cryptoMode` | Must be `1` (`AES-256 (PSK)`) |
| `0x23` | `signature` | 16-byte AES-GCM auth tag |
| `0x7F` | `encryptedMessage` | Ciphertext |

The decrypted bytes inside `encryptedMessage` are themselves a TLV payload. After decryption, those inner TLV fields are parsed and appended to the outer parsed message. The `encryptedMessage` field is removed from the final decrypted object.

## Encrypted Downlink ACK Shape

When an uplink contains `encryptedMessage`, the ACK downlink is encrypted with the same AES-GCM TLV envelope. The `encryptedMessage` value is the TLV-encoded downlink body, including `0x14` (`uplinkAck`) set to the received `fCntUp`. Any pending `0x7C` downlink payloads are encrypted in the same inner TLV body.

The outer encrypted downlink contains:

| Tag | Field | Purpose |
| --- | --- | --- |
| `0x01` | `version` | Protocol version and AAD |
| `0x1A` | `stid` | Device STID and AAD |
| `0x21` | `iv` | 96-bit AES-GCM IV |
| `0x22` | `cryptoMode` | `1` (`AES-256 (PSK)`) |
| `0x23` | `signature` | 16-byte AES-GCM auth tag |
| `0x7F` | `encryptedMessage` | Ciphertext containing the TLV-encoded ACK |

## AES-GCM Inputs

The implementation uses:

- Algorithm: `aes-256-gcm`
- Key: 32-byte pre-shared key
- IV: 96-bit value of tag `0x21`
- AAD: the original raw TLV bytes for every field except tag `0x7F` and tag `0x23`
- Ciphertext: value of `encryptedMessage`, which may be empty for authentication-only messages
- Auth tag: value of `signature`

AAD must preserve the exact original TLV bytes and field order from the received message. Re-encoding the plaintext fields may not produce byte-for-byte identical AAD if the incoming message used a different valid ordering.

## IV Format

The IV is 96 bits long:

| Bytes | Size | Contents |
| --- | --- | --- |
| `0..7` | 64 bits | Random data |
| `8..11` | 32 bits | Message timestamp, unsigned big-endian |

Encrypted uplinks carry the anti-replay timestamp in the last 32 bits of the IV, not in a plaintext TLV timestamp field. A message with timestamp `1712345678` (`0x6610524E`) and random IV prefix `2021222324252627` uses this IV:

```text
20212223242526276610524E
```

The server validates the IV timestamp against its current clock. The allowed skew is configured with `ENCRYPTION_ALLOWED_CLOCK_SKEW_SECONDS` and defaults to `60`. If `0x24` (`unsyncedClock`) is present, timestamp validation is skipped and the IV is treated as 96 bits of random data.

## Worked Example

This example uses fixed values so the output is reproducible.

Key:

```text
000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
```

Outer plaintext fields:

| Field | Value |
| --- | --- |
| `version` | `1` encoded exactly as `01020001` |
| `stid` | `00001111` |
| `iv` | `20212223242526276610524E` |
| `cryptoMode` | `1` (`AES-256 (PSK)`) |

Outer plaintext TLV bytes, used as AAD:

```text
010200011A0400001111210C20212223242526276610524E220101
```

AAD field breakdown:

| Field | TLV bytes |
| --- | --- |
| `version` | `01020001` |
| `stid` | `1A0400001111` |
| `iv` | `210C20212223242526276610524E` |
| `cryptoMode` | `220101` |

Inner plaintext fields:

| Field | Value |
| --- | --- |
| `payload` | `ABCD` |
| `fCntUp` | `12355` |
| `battery` | `66` |
| `clickType` | `double` |

Inner plaintext TLV bytes before encryption:

```text
7E02ABCD10023043800080010142800080020102
```

AES-GCM output:

| Part | Hex |
| --- | --- |
| Ciphertext | `8D94FE37112A8B499BA9ACF2C8B622AE07BAEB68` |
| `signature` value | `579AFACF9C5FE8A4DAAAB9CFEAE8C71E` |
| `encryptedMessage` value | `8D94FE37112A8B499BA9ACF2C8B622AE07BAEB68` |

Full uplink TLV payload:

```text
010200011A0400001111210C20212223242526276610524E2201012310579AFACF9C5FE8A4DAAAB9CFEAE8C71E7F148D94FE37112A8B499BA9ACF2C8B622AE07BAEB68
```

After decryption, the parsed uplink contains:

```json
{
  "version": 1,
  "stid": "00001111",
  "iv": "20212223242526276610524E",
  "cryptoMode": "AES-256 (PSK)",
  "payload": "ABCD",
  "fCntUp": 12355,
  "battery": 66,
  "clickType": "double"
}
```

## Authentication Behavior

Because every plaintext TLV field except `0x7F` and `0x23` is included in AAD, changing any authenticated plaintext field changes the AES-GCM authentication result. For example, changing one byte in `stid` while leaving `encryptedMessage` and `signature` untouched causes decryption to fail authentication.

Changing `cryptoMode` also fails before decryption unless it remains `1` (`AES-256 (PSK)`).
