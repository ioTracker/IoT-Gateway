# TLV Tag Spec

Generated from `tlv-tag-spec.json`.

## Protocol

| Tag | Field Name | Datatype | Description | Example | Allow Multiple | In Uplink | In Downlink | Max Length (value) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `0x01` | `version` | `uint16` | Protocol version | 1 | `FALSE` | `TRUE` | `TRUE` |  |

## Control Flow

| Tag | Field Name | Datatype | Description | Example | Allow Multiple | In Uplink | In Downlink | Max Length (value) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `0x02` | `isConfirmed` | `bool` | Indication to the server if the sender opens a receive window |  | `FALSE` | `TRUE` | `FALSE` |  |

## Payload

| Tag | Field Name | Datatype | Description | Example | Allow Multiple | In Uplink | In Downlink | Max Length (value) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `0x7E` | `payload` | `buffer` | Contains legacy encoded payload data |  | `FALSE` | `TRUE` | `FALSE` |  |

## Device

| Tag | Field Name | Datatype | Description | Example | Allow Multiple | In Uplink | In Downlink | Max Length (value) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `0x1A` | `stid` | `buffer` | Device STID |  | `FALSE` | `TRUE` | `FALSE` |  |
| `0x1B` | `imei` | `buffer` | Device IMEI |  | `FALSE` | `TRUE` | `TRUE` |  |
| `0x1C` | `iccid` | `buffer` | Device ICCID |  | `FALSE` | `TRUE` | `FALSE` |  |
| `0x1d` | `deviceVersions` | `struct` | 16B: hwVersion(hex), stmVersion(hex), nrfVersion(hex), espVersion(hex) |  | `FALSE` | `TRUE` | `FALSE` |  |

## Cryptography

| Tag | Field Name | Datatype | Description | Example | Allow Multiple | In Uplink | In Downlink | Max Length (value) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `0x21` | `iv` | `buffer` | 96-bit AES-GCM IV |  | `FALSE` | `TRUE` | `TRUE` |  |
| `0x22` | `cryptoMode` | `enum` | Cryptography mode Enum: 0: Plaintext, 1: AES-256 (PSK), 2: AES-256 (PKI) |  | `FALSE` | `TRUE` | `TRUE` |  |
| `0x23` | `signature` | `buffer` | Message signature (AES GCM Auth Tag) |  | `FALSE` | `TRUE` | `TRUE` |  |
| `0x24` | `unsyncedClock` | `bool` | Device has no confirmed timestamp |  | `FALSE` | `TRUE` | `FALSE` |  |
| `0x7F` | `encryptedMessage` | `buffer` | Encrypted message payload |  | `FALSE` | `TRUE` | `TRUE` |  |

## Counters

| Tag | Field Name | Datatype | Description | Example | Allow Multiple | In Uplink | In Downlink | Max Length (value) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `0x10` | `fCntUp` | `uint32` |  |  | `FALSE` | `TRUE` | `FALSE` |  |
| `0x11` | `fCntDown` | `uint32` |  |  | `FALSE` | `TRUE` | `TRUE` |  |
| `0x15` | `retransmitCount` | `uint32` | Increased on every retransmit and reset on establish |  | `FALSE` | `TRUE` | `FALSE` |  |
| `0x13` | `downlinkAck` | `uint32` | fCntDown of ACK'ed downlink. |  | `FALSE` | `FALSE` | `FALSE` |  |
| `0x14` | `uplinkAck` | `uint32` | fCntUp of ACK'ed uplink. |  | `FALSE` | `FALSE` | `FALSE` |  |

## Radio

| Tag | Field Name | Datatype | Description | Example | Allow Multiple | In Uplink | In Downlink | Max Length (value) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `0xA001` | `rat` | `enum` | Radio Access Technology Enum: 7: LTE-M, 9: NB-IOT |  | `FALSE` | `FALSE` | `FALSE` |  |
| `0xA002` | `rsrp` | `int16` | Signal strength |  | `FALSE` | `FALSE` | `FALSE` |  |
| `0xA003` | `rsrq` | `int16` | Signal quality |  | `FALSE` | `FALSE` | `FALSE` |  |
| `0xA004` | `cellularStatus` | `struct` | 19B packed iot_cellular_status_t. Multi-byte members are big-endian; valid indicates which measurements are present. |  | `FALSE` | `TRUE` | `FALSE` |  |

## Telemetry

| Tag | Field Name | Datatype | Description | Example | Allow Multiple | In Uplink | In Downlink | Max Length (value) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `0x8001` | `battery` | `uint8` |  |  | `FALSE` | `TRUE` | `FALSE` |  |
| `0x8002` | `clickType` | `enum` | Click type that initiated messages Enum: 0: noClick, 1: single, 2: double, 3: long |  | `FALSE` | `TRUE` | `FALSE` |  |
| `0x8003` | `batteryStatus` | `struct` | 4B: socDisplay(uint8), flags(bit0=lowTemp,bit1=veryLowTemp,bit2=replaceSoon,bit3=highStandbyCurrent,bit4-5=batEvalState[0=inUse,1=old,2=newBatteryEval,3=bad],bit6=esrQualityLimited,bit7=impedanceSocLimited), daysRemaining(uint16) |  | `FALSE` | `TRUE` | `FALSE` |  |

## Downlink

| Tag | Field Name | Datatype | Description | Example | Allow Multiple | In Uplink | In Downlink | Max Length (value) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `0x7C` | `downlinks` | `buffer` |  |  | `TRUE` | `FALSE` | `TRUE` |  |

## Notes

- This spec is intentionally permissive. in_uplink and in_downlink are descriptive only and are not enforced by the parser.
- All fields are unique unless can_repeat is true.
- For type=buffer, max_length is the maximum byte length when provided.
- Integer types use embedded-style names such as uint8, uint24, uint32, and int16. Parsers decode incoming integer payloads using the TLV length field; encoders use the type width.
- For type=struct, fields describe fixed byte ranges within the value. Struct fields can also be virtual values derived from an earlier member with derived_from, shift_right, and mask. Decoded structs include an uppercase hexadecimal _raw field.

> [!NOTE]
> TLV tag and length headers use related but different extended encodings.
>
> Tags are valid only in the ranges `0x01` through `0x7F` and `0x8000` through `0xFFFF`. Tag values from `0x0080` through `0x7FFF` are not allowed.
>
> Lengths use `0x00` through `0x7F` directly for values 0 through 127. Extended length headers use `0x8000` through `0xFFFF`, offset so that `0x8000` is length 128.
>
> Examples: `0x00` is 0, `0x7F` is 127, `0x8000` is 128, `0x8001` is 129, and `0xFFFF` is 32895.
