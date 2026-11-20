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
| `0x8004` | `batteryExtended` | `struct` | 91-byte version 1 value (94 bytes with header). Sent when BatteryExtendedReport=true in normal/full uplinks, encrypted or unencrypted. Excluded from bootstrap. |  | `FALSE` | `TRUE` | `FALSE` |  |

## Downlink

| Tag | Field Name | Datatype | Description | Example | Allow Multiple | In Uplink | In Downlink | Max Length (value) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `0x7C` | `downlinks` | `buffer` |  |  | `TRUE` | `FALSE` | `TRUE` |  |

## batteryExtended

91-byte version 1 value (94 bytes with header). Sent when BatteryExtendedReport=true in normal/full uplinks, encrypted or unencrypted. Excluded from bootstrap.

Offsets 3–40 describe the model at payload construction. Offsets 41–90 describe the previous completed cellular measurement session and require sessionValid. A skipped ESR measurement can still produce a valid session, with the filter state left unchanged. All multibyte values are big-endian. Invalid fields are omitted from decoded JSON, with the ESR filter input represented as 0 for valid sessions with results other than 2 or 3.

| Offset | Bytes | Field | Datatype | Unit / scale | Description |
| --- | --- | --- | --- | --- | --- |
| 0 | 1 | version | uint8 |  | Format version, currently 1. |
| 1 | 1 | flags | bitfield |  | Session and battery model validity flags. |
| 2 | 1 | esrResult | uint8 |  | ESR result code for the previous session. Requires sessionValid. |
| 3 | 1 | socAbsolute | uint8 | 0–254 | SOC from coulomb counting. Multiply by 100 / 254 for percent. |
| 4 | 1 | socCompensated | uint8 | 0–254 | Impedance-compensated SOC. Multiply by 100 / 254 for percent. |
| 5 | 2 | socAbsolutePermille | uint16 | ‰ | Absolute SOC (0–1000). |
| 7 | 2 | socNowPermille | uint16 | ‰ | Current SOC after impedance limiting (0–1000). |
| 9 | 2 | socEstimatedPermille | uint16 | ‰ | Estimated SOC with temperature compensation (0–1000). |
| 11 | 2 | daysRemainingAbsolute | uint16 | days | Estimated life without impedance compensation. 65535 means unknown. |
| 13 | 2 | daysRemainingCompensated | uint16 | days | Estimated life with impedance compensation. 65535 means unknown. |
| 15 | 8 | chargeUsedTotal | uint64 | mAms | Total charge used. 3600000 mAms equals 1 mAh. The gateway returns a decimal string. |
| 23 | 4 | resistanceNormalized | uint32 | mΩ | Normalized resistance used by the current model. |
| 27 | 4 | acceptedEsrAge | uint32 | s | Age of the last accepted cellular ESR measurement. Requires acceptedEsrValid. |
| 31 | 2 | modelTemperature | int16 | °C | Temperature at the last battery model evaluation. |
| 33 | 4 | esrRawMaximum | uint32 | mΩ | Highest raw ESR since battery reset. |
| 37 | 4 | esrFilteredMaximum | uint32 | mΩ | Highest filtered ESR since battery reset. |
| 41 | 4 | sessionUplinkCounter | uint32 |  | Uplink counter for session context only. It does not confirm delivery. |
| 45 | 4 | sessionDuration | uint32 | ms | Session duration. |
| 49 | 4 | sessionCharge | uint32 | mAms | Session charge. Requires sessionSampleCount > 0. |
| 53 | 4 | sessionSampleCount | uint32 | samples | Sample count. |
| 57 | 2 | sessionVcapStart | uint16 | mV | Supercapacitor voltage at session start. |
| 59 | 2 | sessionVcapEnd | uint16 | mV | Supercapacitor voltage at session end. |
| 61 | 2 | sessionVbatMin | uint16 | mV | Minimum battery voltage. Requires sessionVbatValid. |
| 63 | 2 | sessionVbatMax | uint16 | mV | Maximum battery voltage. Requires sessionVbatValid. |
| 65 | 2 | sessionTemperature | int16 | °C | Temperature at session completion. |
| 67 | 4 | sessionCurrentAverage | uint32 | µA | Average current. Requires sessionSampleCount > 0. |
| 71 | 4 | sessionCurrentPeak | uint32 | µA | Peak current. Requires sessionSampleCount > 0. |
| 75 | 4 | sessionCurrentAtVbatMin | uint32 | µA | Current at minimum battery voltage. Requires sessionVbatValid. |
| 79 | 4 | sessionEsrRaw | uint32 | mΩ | Raw ESR. Requires sessionVbatValid, sessionCurrentPeak > 0 and esrResult other than 1. |
| 83 | 4 | sessionEsrInput | uint32 | mΩ | Accepted ESR filter input for esrResult 2 or 3. Otherwise 0. |
| 87 | 4 | sessionEsrFiltered | uint32 | mΩ | Filter state after the session. 0 means uninitialized. |

### flags

| Bit | Name | Meaning when set |
| --- | --- | --- |
| 0 | `sessionValid` | A previous completed cellular measurement session is available. |
| 1 | `sessionVbatValid` | The session battery voltage measurement is valid. |
| 2 | `acceptedEsrValid` | A previous cellular ESR was accepted and acceptedEsrAge is valid. |
| 3 | `ignoreBatteryImpedance` | Display absolute SOC and days when set, or compensated SOC and days when clear. |

Reserved bits are 4–7 (currently zero).

### esrResult

| Value | Name | Description |
| --- | --- | --- |
| 0 | `noSamples` | No samples collected. |
| 1 | `noEsr` | No usable ESR value. |
| 2 | `accepted` | ESR accepted. |
| 3 | `limited` | ESR accepted with limited filter input. |
| 4 | `skippedContext` | ESR skipped due to session context. |
| 5 | `skippedVcap` | ESR skipped due to low initial supercapacitor voltage. |
| 6 | `skippedCurrent` | ESR skipped due to insufficient peak current. |
| 7 | `skippedVbatMax` | ESR skipped because maximum battery voltage was outside the allowed range. |
| 8 | `skippedVbatMin` | ESR skipped due to low minimum battery voltage. |

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
