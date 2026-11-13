const crypto = require("crypto");
const tlvSchema = require("../tlv-tag-spec.json");

const TLV_AAD_SYMBOL = Symbol("tlvAdditionalAuthenticatedData");
const ENCRYPTED_MESSAGE_TAG = 0x7F;
const SIGNATURE_TAG = 0x23;
const DEFAULT_ALLOWED_CLOCK_SKEW_SECONDS = 60;

function toBuffer(input) {
  if (Buffer.isBuffer(input)) {
    return input;
  }
  if (input instanceof Uint8Array) {
    return Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  }
  if (input instanceof ArrayBuffer) {
    return Buffer.from(input);
  }

  throw new TypeError("TLV payload input must be a Buffer, Uint8Array, or ArrayBuffer");
}

function toBase64(value) {
  return Buffer.from(value).toString("base64");
}

function inferDirection(payloadBuffer) {
  if (payloadBuffer.length === 0) {
    throw new Error("Cannot infer direction from an empty TLV payload");
  }

  return "unknown";
}

function getFieldDefinitions(direction) {
  void direction;
  return tlvSchema.fields.filter((field) => field.name);
}

function parseTagNumber(tag) {
  const normalizedTag = typeof tag === "number" ? tag.toString(16) : String(tag);
  const hex = normalizedTag.startsWith("0x") || normalizedTag.startsWith("0X")
    ? normalizedTag.slice(2)
    : normalizedTag;
  return Number.parseInt(hex, 16);
}

function formatTag(tag) {
  const hex = tag.toString(16).toUpperCase();
  return `0x${hex.length > 1 ? hex : hex.padStart(2, "0")}`;
}

function assertNonNegativeInteger(value, label) {
  if (!Number.isInteger(value) || value < 0) {
    throw new TypeError(`${label} must be a non-negative integer`);
  }
}

function encodeTagHeaderValue(value, label) {
  assertNonNegativeInteger(value, label);

  if (value >= 0x01 && value <= 0x7F) {
    return Buffer.from([value]);
  }

  if (value >= 0x8000 && value <= 0xFFFF) {
    return Buffer.from([
      (value >> 8) & 0xFF,
      value & 0xFF
    ]);
  }

  throw new Error(`${label} must be between 0x01 and 0x7F or between 0x8000 and 0xFFFF`);
}

function encodeLengthHeaderValue(value, label) {
  assertNonNegativeInteger(value, label);

  if (value <= 0x7F) {
    return Buffer.from([value]);
  }

  if (value > 0x807F) {
    throw new Error(`${label} exceeds the TLV length header limit`);
  }

  const encodedValue = value + 0x7F80;
  return Buffer.from([
    (encodedValue >> 8) & 0xFF,
    encodedValue & 0xFF
  ]);
}

function decodeTagHeaderValue(buffer, offset) {
  if (offset >= buffer.length) {
    throw new Error(`Incomplete TLV tag at byte offset ${offset}`);
  }

  const firstByte = buffer[offset];
  if ((firstByte & 0x80) === 0) {
    if (firstByte === 0x00) {
      throw new Error("Invalid TLV tag 0x00");
    }

    return {
      value: firstByte,
      nextOffset: offset + 1
    };
  }

  if (offset + 1 >= buffer.length) {
    throw new Error(`Incomplete TLV tag at byte offset ${offset}`);
  }

  return {
    value: (firstByte << 8) | buffer[offset + 1],
    nextOffset: offset + 2
  };
}

function decodeLengthHeaderValue(buffer, offset) {
  if (offset >= buffer.length) {
    throw new Error(`Incomplete TLV length at byte offset ${offset}`);
  }

  const firstByte = buffer[offset];
  if ((firstByte & 0x80) === 0) {
    return {
      value: firstByte,
      nextOffset: offset + 1
    };
  }

  if (offset + 1 >= buffer.length) {
    throw new Error(`Incomplete TLV length at byte offset ${offset}`);
  }

  const encodedValue = (firstByte << 8) | buffer[offset + 1];

  return {
    value: encodedValue - 0x7F80,
    nextOffset: offset + 2
  };
}

function buildFieldMap(direction) {
  return new Map(
    getFieldDefinitions(direction).map((field) => [parseTagNumber(field.tag), field])
  );
}

function buildFieldNameMap(direction) {
  return new Map(
    getFieldDefinitions(direction)
      .filter((field) => field.name)
      .map((field) => [field.name, field])
  );
}

function normalizeTlvInputObject(input) {
  if (!input || Array.isArray(input) || typeof input !== "object") {
    throw new TypeError("TLV input must be a plain object");
  }

  return input;
}

function inferDirectionFromObject(inputObject) {
  const fieldNames = new Set(getFieldDefinitions().map((field) => field.name));
  if (Object.keys(inputObject).every((key) => fieldNames.has(key))) {
    return "unknown";
  }

  throw new Error("Unable to infer TLV direction from input object");
}

function validateIntegerString(field, valueString, tag) {
  if (!/^-?\d+$/.test(valueString)) {
    throw new Error(`Field ${tag} (${field.name}) must contain only decimal digits`);
  }
}

function parseIntegerType(type) {
  const match = /^(u?int)(\d+)$/.exec(String(type));
  if (!match) {
    return null;
  }

  const bitLength = Number(match[2]);
  if (!Number.isInteger(bitLength) || bitLength < 8 || bitLength % 8 !== 0) {
    return null;
  }

  return {
    signed: match[1] === "int",
    bytes: bitLength / 8,
    bits: bitLength
  };
}

function isIntegerField(field) {
  return parseIntegerType(field.type) !== null;
}

function usesBinaryIntegerEncoding(field) {
  return isIntegerField(field);
}

function bigintToNumber(value, field) {
  const numberValue = Number(value);
  if (!Number.isSafeInteger(numberValue)) {
    throw new Error(`Field ${field.tag} (${field.name}) exceeds JavaScript safe integer range`);
  }
  return numberValue;
}

function decodeIntegerValue(field, valueBuffer) {
  if (valueBuffer.length === 0) {
    throw new Error(`Field ${field.tag} (${field.name}) may not be empty`);
  }

  let value = 0n;
  const bytes = field.endianness === "little" ? [...valueBuffer].reverse() : valueBuffer;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }

  const integerType = parseIntegerType(field.type);
  const signByte = field.endianness === "little"
    ? valueBuffer[valueBuffer.length - 1]
    : valueBuffer[0];
  if (integerType && integerType.signed && (signByte & 0x80) !== 0) {
    value -= 1n << BigInt(valueBuffer.length * 8);
  }

  return bigintToNumber(value, field);
}

function parseBitRange(bitDefinition) {
  if (Number.isInteger(bitDefinition.bit)) {
    return { start: bitDefinition.bit, end: bitDefinition.bit };
  }

  const match = /^(\d+)-(\d+)$/.exec(String(bitDefinition.bits));
  if (!match) {
    throw new Error(`Invalid bit range ${bitDefinition.bits}`);
  }
  return { start: Number(match[1]), end: Number(match[2]) };
}

function decodeBitfieldValue(field, valueBuffer) {
  const rawValue = BigInt(decodeIntegerValue({ ...field, type: `uint${valueBuffer.length * 8}` }, valueBuffer));
  const decoded = {};

  for (const bitDefinition of field.bits || []) {
    const { start, end } = parseBitRange(bitDefinition);
    const width = end - start + 1;
    const numericValue = Number((rawValue >> BigInt(start)) & ((1n << BigInt(width)) - 1n));
    decoded[bitDefinition.name] = bitDefinition.enum && Object.prototype.hasOwnProperty.call(bitDefinition.enum, String(numericValue))
      ? bitDefinition.enum[String(numericValue)]
      : width === 1 ? numericValue !== 0 : numericValue;
  }

  return decoded;
}

function decodeStructValue(field, valueBuffer) {
  const decoded = {};

  for (const member of field.fields || []) {
    if (member.derived_from) {
      continue;
    }
    if (!Number.isInteger(member.offset) || !Number.isInteger(member.size) || member.offset < 0 || member.size < 1 || member.offset + member.size > valueBuffer.length) {
      throw new Error(`Field ${field.tag} (${field.name}) has invalid struct member ${member.name}`);
    }
    const memberBuffer = valueBuffer.subarray(member.offset, member.offset + member.size);
    if (member.type === "bitfield") {
      decoded[member.name] = decodeBitfieldValue(member, memberBuffer);
    } else if (member.type === "enum") {
      const enumValue = String(decodeUnsignedInteger(memberBuffer));
      if (!member.enum || !Object.prototype.hasOwnProperty.call(member.enum, enumValue)) {
        throw new Error(`Field ${field.tag} (${field.name}) struct member ${member.name} contains unknown enum value ${enumValue}`);
      }
      decoded[member.name] = member.enum[enumValue];
    } else if (isIntegerField(member)) {
      decoded[member.name] = decodeIntegerValue(member, memberBuffer);
    } else {
      decoded[member.name] = memberBuffer.toString("hex").toUpperCase();
    }
  }

  for (const member of field.fields || []) {
    if (!member.derived_from) {
      continue;
    }
    if (!Object.prototype.hasOwnProperty.call(decoded, member.derived_from) || !Number.isInteger(decoded[member.derived_from])) {
      throw new Error(`Field ${field.tag} (${field.name}) has invalid derived struct member ${member.name}`);
    }

    let value = decoded[member.derived_from];
    if (member.shift_right !== undefined) {
      if (!Number.isInteger(member.shift_right) || member.shift_right < 0) {
        throw new Error(`Field ${field.tag} (${field.name}) has invalid shift_right for struct member ${member.name}`);
      }
      value >>>= member.shift_right;
    }
    if (member.mask !== undefined) {
      if (!Number.isInteger(member.mask) || member.mask < 0) {
        throw new Error(`Field ${field.tag} (${field.name}) has invalid mask for struct member ${member.name}`);
      }
      value &= member.mask;
    }
    decoded[member.name] = value;
  }

  decoded._raw = valueBuffer.toString("hex").toUpperCase();
  return decoded;
}

function decodeFieldValue(field, valueBuffer) {
  if (field.kind === "container" || field.type === "buffer") {
    return Buffer.from(valueBuffer);
  }

  if (field.type === "struct") {
    return decodeStructValue(field, valueBuffer);
  }

  if (isIntegerField(field)) {
    if (usesBinaryIntegerEncoding(field)) {
      return decodeIntegerValue(field, valueBuffer);
    }

    const valueString = valueBuffer.toString("utf8");
    validateIntegerString(field, valueString, field.tag);
    return Number(valueString);
  }

  if (field.type === "enum") {
    const valueString = String(decodeUnsignedInteger(valueBuffer));
    validateIntegerString(field, valueString, field.tag);
    if (!field.enum || !Object.prototype.hasOwnProperty.call(field.enum, valueString)) {
      throw new Error(`Field ${field.tag} (${field.name}) contains unknown enum value ${valueString}`);
    }
    return field.enum[valueString];
  }

  if (field.type === "bool") {
    return decodeUnsignedInteger(valueBuffer) !== 0;
  }

  return valueBuffer.toString("utf8");
}

function getEncodedLengthForValidation(field, valueBuffer) {
  if (field.kind === "container" || field.type === "buffer" || field.type === "struct" || isIntegerField(field) || field.type === "enum" || field.type === "bool") {
    return valueBuffer.length;
  }

  return valueBuffer.toString("utf8").length;
}

function decodeUnsignedInteger(valueBuffer) {
  if (valueBuffer.length === 0) {
    return 0;
  }

  let value = 0;
  for (const byte of valueBuffer) {
    value = (value << 8) | byte;
  }
  return value;
}

function encodeBufferValue(field, rawValue) {
  if (Buffer.isBuffer(rawValue)) {
    return Buffer.from(rawValue);
  }

  if (rawValue instanceof Uint8Array) {
    return Buffer.from(rawValue.buffer, rawValue.byteOffset, rawValue.byteLength);
  }

  if (rawValue instanceof ArrayBuffer) {
    return Buffer.from(rawValue);
  }

  if (typeof rawValue === "string") {
    if (!/^[0-9a-fA-F]*$/.test(rawValue) || rawValue.length % 2 !== 0) {
      throw new Error(`Field ${field.tag} (${field.name}) must be a valid even-length hexadecimal string`);
    }
    return Buffer.from(rawValue, "hex");
  }

  throw new TypeError(`Field ${field.tag} (${field.name}) must be a Buffer, Uint8Array, ArrayBuffer, or hex string`);
}

function encodeEnumValue(field, rawValue) {
  const rawString = String(rawValue);

  if (field.enum && Object.prototype.hasOwnProperty.call(field.enum, rawString)) {
    return encodeIntegerValue(field, Number(rawString));
  }

  if (field.enum) {
    const enumEntry = Object.entries(field.enum).find(([, label]) => label === rawValue);
    if (enumEntry) {
      return encodeIntegerValue(field, Number(enumEntry[0]));
    }
  }

  throw new Error(`Field ${field.tag} (${field.name}) contains unknown enum value ${rawValue}`);
}

function encodeIntegerValue(field, rawValue) {
  if (typeof rawValue !== "number" && typeof rawValue !== "string") {
    throw new TypeError(`Field ${field.tag} (${field.name}) must be a number or decimal string`);
  }

  const valueString = String(rawValue).trim();
  if (!/^-?\d+$/.test(valueString)) {
    throw new TypeError(`Field ${field.tag} (${field.name}) must be an integer`);
  }

  const numericValue = BigInt(valueString);
  const integerType = parseIntegerType(field.type);
  const byteLength = integerType ? integerType.bytes : null;
  const isSigned = integerType ? integerType.signed : false;

  if (byteLength !== null) {
    const bitLength = BigInt(byteLength * 8);
    const minValue = isSigned ? -(1n << (bitLength - 1n)) : 0n;
    const maxValue = isSigned ? (1n << (bitLength - 1n)) - 1n : (1n << bitLength) - 1n;

    if (numericValue < minValue || numericValue > maxValue) {
      throw new RangeError(
        `Field ${field.tag} (${field.name}) must be between ${minValue.toString()} and ${maxValue.toString()}`
      );
    }

    let encodedValue = numericValue;
    if (encodedValue < 0) {
      encodedValue += 1n << bitLength;
    }

    const bytes = Buffer.alloc(byteLength);
    for (let index = byteLength - 1; index >= 0; index -= 1) {
      bytes[index] = Number(encodedValue & 0xFFn);
      encodedValue >>= 8n;
    }
    return bytes;
  }

  if (numericValue < 0) {
    throw new TypeError(`Field ${field.tag} (${field.name}) must be a non-negative integer`);
  }

  if (numericValue === 0) {
    return Buffer.from([0x00]);
  }
  if (numericValue <= 0xFFn) {
    return Buffer.from([Number(numericValue)]);
  }

  const bytes = [];
  let remainingValue = numericValue;
  while (remainingValue > 0n) {
    bytes.unshift(Number(remainingValue & 0xFFn));
    remainingValue >>= 8n;
  }
  return Buffer.from(bytes);
}

function encodeFieldValue(field, rawValue) {
  if (field.kind === "container" || field.type === "buffer") {
    return encodeBufferValue(field, rawValue);
  }

  if (field.type === "struct") {
    if (rawValue && typeof rawValue === "object" && !Buffer.isBuffer(rawValue) && Object.prototype.hasOwnProperty.call(rawValue, "_raw")) {
      return encodeBufferValue(field, rawValue._raw);
    }
    return encodeBufferValue(field, rawValue);
  }

  if (isIntegerField(field)) {
    return encodeIntegerValue(field, rawValue);
  }

  if (field.type === "enum") {
    return encodeEnumValue(field, rawValue);
  }

  if (field.type === "bool") {
    return Buffer.from([rawValue ? 1 : 0]);
  }

  return Buffer.from(String(rawValue), "utf8");
}

function validateEncodedField(field, valueBuffer) {
  const encodedLength = getEncodedLengthForValidation(field, valueBuffer);
  if (field.length !== undefined && field.length !== null && encodedLength !== field.length) {
    throw new Error(
      `Field ${field.tag} (${field.name}) must have length ${field.length}, received ${encodedLength}`
    );
  }
  if (field.max_length !== undefined && field.max_length !== null && encodedLength > field.max_length) {
    throw new Error(
      `Field ${field.tag} (${field.name}) exceeds max_length ${field.max_length} with length ${encodedLength}`
    );
  }

  if (valueBuffer.length > 0x807F) {
    throw new Error(`Field ${field.tag} (${field.name}) exceeds the TLV length limit`);
  }
}

function encodeTlvPayload(input, options = {}) {
  const inputObject = normalizeTlvInputObject(input);
  const direction = options.direction || inferDirectionFromObject(inputObject);
  const fieldNameMap = buildFieldNameMap(direction);
  const fieldDefinitions = getFieldDefinitions(direction);
  const encodedFields = [];

  for (const key of Object.keys(inputObject)) {
    if (!fieldNameMap.has(key)) {
      throw new Error(`Unknown TLV field ${key}`);
    }
  }

  for (const field of fieldDefinitions) {
    if (!Object.prototype.hasOwnProperty.call(inputObject, field.name)) {
      continue;
    }

    const rawValue = inputObject[field.name];
    const values = field.can_repeat ? rawValue : [rawValue];

    if (field.can_repeat && !Array.isArray(rawValue)) {
      throw new TypeError(`Field ${field.tag} (${field.name}) must be an array because can_repeat is true`);
    }

    for (const value of values) {
      const valueBuffer = encodeFieldValue(field, value);
      validateEncodedField(field, valueBuffer);

      const tagNumber = parseTagNumber(field.tag);
      encodedFields.push(Buffer.concat([
        encodeTagHeaderValue(tagNumber, `Field ${field.tag} (${field.name}) tag`),
        encodeLengthHeaderValue(valueBuffer.length, `Field ${field.tag} (${field.name}) length`),
        valueBuffer
      ]));
    }
  }

  return Buffer.concat(encodedFields).toString("hex").toUpperCase();
}

function parseTlvPayload(input, options = {}) {
  const payloadBuffer = toBuffer(input);
  const direction = options.direction || inferDirection(payloadBuffer);
  const fieldMap = buildFieldMap(direction);
  const parsed = {};
  const additionalAuthenticatedFields = [];

  let offset = 0;
  while (offset < payloadBuffer.length) {
    const fieldOffset = offset;
    const tagHeader = decodeTagHeaderValue(payloadBuffer, offset);
    const tagNumber = tagHeader.value;
    const tag = formatTag(tagNumber);
    const lengthHeader = decodeLengthHeaderValue(payloadBuffer, tagHeader.nextOffset);
    const length = lengthHeader.value;
    offset = lengthHeader.nextOffset;

    if (offset + length > payloadBuffer.length) {
      throw new Error(`Field ${tag} declares length ${length}, which exceeds the remaining payload`);
    }

    const field = fieldMap.get(tagNumber);
    if (!field) {
      throw new Error(`Unknown TLV tag ${tag}`);
    }

    const valueBuffer = payloadBuffer.subarray(offset, offset + length);
    offset += length;
    const fieldBuffer = payloadBuffer.subarray(fieldOffset, offset);

    if (tagNumber !== ENCRYPTED_MESSAGE_TAG && tagNumber !== SIGNATURE_TAG) {
      additionalAuthenticatedFields.push(fieldBuffer);
    }

    validateEncodedField(field, valueBuffer);

    const value = decodeFieldValue(field, valueBuffer);

    if (field.can_repeat) {
      if (!Object.prototype.hasOwnProperty.call(parsed, field.name)) {
        parsed[field.name] = [];
      }
      parsed[field.name].push(value);
      continue;
    }

    if (Object.prototype.hasOwnProperty.call(parsed, field.name)) {
      throw new Error(`Field ${tag} (${field.name}) may not appear multiple times`);
    }

    parsed[field.name] = value;
  }

  if (Object.prototype.hasOwnProperty.call(parsed, "encryptedMessage")) {
    Object.defineProperty(parsed, TLV_AAD_SYMBOL, {
      value: Buffer.concat(additionalAuthenticatedFields),
      enumerable: false
    });
  }

  return parsed;
}

function getTlvBlocks(input, options = {}) {
  const payloadBuffer = typeof input === "string"
    ? normalizeIncomingTlvPayload(input)
    : toBuffer(input);
  const direction = options.direction || inferDirection(payloadBuffer);
  const fieldMap = buildFieldMap(direction);
  const blocks = [];

  let offset = 0;
  while (offset < payloadBuffer.length) {
    const tagHeader = decodeTagHeaderValue(payloadBuffer, offset);
    const tagNumber = tagHeader.value;
    const tag = formatTag(tagNumber);
    const lengthHeader = decodeLengthHeaderValue(payloadBuffer, tagHeader.nextOffset);
    const length = lengthHeader.value;
    const valueOffset = lengthHeader.nextOffset;

    if (valueOffset + length > payloadBuffer.length) {
      throw new Error(`Field ${tag} declares length ${length}, which exceeds the remaining payload`);
    }

    const field = fieldMap.get(tagNumber);
    if (!field) {
      throw new Error(`Unknown TLV tag ${tag}`);
    }

    const valueBuffer = payloadBuffer.subarray(valueOffset, valueOffset + length);
    blocks.push({
      tag,
      tagName: field.name,
      length,
      value: valueBuffer.toString("hex").toUpperCase()
    });
    offset = valueOffset + length;
  }

  return blocks;
}

function isHexString(value) {
  if (typeof value !== "string") {
    return false;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 && trimmed.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(trimmed);
}

function normalizeIncomingTlvPayload(input) {
  if (Buffer.isBuffer(input) || input instanceof Uint8Array || input instanceof ArrayBuffer) {
    return toBuffer(input);
  }

  if (typeof input === "string") {
    const trimmed = input.trim();
    if (!trimmed) {
      throw new Error("Incoming TLV payload is empty");
    }
    if (!isHexString(trimmed)) {
      throw new Error("Incoming TLV payload must be a Buffer, Uint8Array, ArrayBuffer, or even-length hexadecimal string");
    }
    return Buffer.from(trimmed, "hex");
  }

  throw new TypeError("Incoming TLV payload must be a Buffer, Uint8Array, ArrayBuffer, or hexadecimal string");
}

function buildTlvMetadata(parsed) {
  const metadata = {
    version: parsed.version
  };

  for (const field of ["imei", "iccid", "deviceVersions", "versions"]) {
    if (Object.prototype.hasOwnProperty.call(parsed, field)) {
      metadata[field] = Buffer.isBuffer(parsed[field])
        ? parsed[field].toString("hex").toUpperCase()
        : parsed[field];
    }
  }
  if (Object.prototype.hasOwnProperty.call(parsed, "battery")) {
    metadata.battery = parsed.battery;
  }
  if (Object.prototype.hasOwnProperty.call(parsed, "clickType")) {
    metadata.clickType = parsed.clickType;
  }

  return metadata;
}

function getTlvDeviceId(parsed) {
  const deviceId = parsed.stid || parsed.deviceId || parsed.imei;

  if (!deviceId) {
    throw new Error("Incoming TLV payload does not contain a device identifier (expected stid, deviceId, or imei)");
  }

  if (Buffer.isBuffer(deviceId)) {
    return deviceId.toString("hex").toUpperCase();
  }

  return deviceId;
}

function buildTlvEnvelope(parsed) {
  const deviceId = parsed.stid || parsed.deviceId || parsed.imei;

  if (!deviceId) {
    throw new Error("Incoming TLV payload does not contain a device identifier (expected stid, deviceId, or imei)");
  }

  const metadata = buildTlvMetadata(parsed);

  if (!parsed.encryptedMessage) {
    return {
      deviceId,
      metadata,
      plaintextPayload: parsed,
      original: parsed
    };
  }

  if (!parsed.iv) {
    throw new Error("Incoming TLV payload contains encryptedMessage but does not contain iv");
  }

  return {
    deviceId,
    encryptedPayload: toBase64(parsed.encryptedMessage),
    iv: toBase64(parsed.iv),
    metadata,
    original: parsed
  };
}

function parseTlvUplinkMessage(rawInput) {
  return parseTlvPayload(normalizeIncomingTlvPayload(rawInput), { direction: "uplink" });
}

function isAes256PskCryptoMode(value) {
  return value === 1 || value === "1" || value === "AES-256 (PSK)";
}

function normalizeAllowedClockSkewSeconds(value) {
  const numericValue = value === undefined
    ? DEFAULT_ALLOWED_CLOCK_SKEW_SECONDS
    : Number(value);
  if (!Number.isFinite(numericValue) || numericValue < 0) {
    throw new TypeError("allowedClockSkewSeconds must be a non-negative number");
  }
  return numericValue;
}

function normalizeEncryptionKey(key) {
  if (Buffer.isBuffer(key)) {
    return key;
  }

  if (typeof key === "string") {
    const trimmed = key.trim();
    if (!isHexString(trimmed)) {
      throw new Error("Encryption key must be an even-length hexadecimal string");
    }
    return Buffer.from(trimmed, "hex");
  }

  throw new TypeError("Encryption key must be a Buffer or hexadecimal string");
}

function getCurrentTimestampSeconds(options) {
  if (options.currentTimestampSeconds !== undefined) {
    return Number(options.currentTimestampSeconds);
  }
  return Math.floor(Date.now() / 1000);
}

function validateEncryptedMessageIv(message, ivBuffer, options) {
  if (ivBuffer.length !== 12) {
    throw new Error("Incoming TLV payload contains encryptedMessage but iv is not 96 bits");
  }

  if (Object.prototype.hasOwnProperty.call(message, "unsyncedClock")) {
    return;
  }

  const currentTimestampSeconds = getCurrentTimestampSeconds(options);
  if (!Number.isFinite(currentTimestampSeconds)) {
    throw new TypeError("currentTimestampSeconds must be a finite number");
  }

  const allowedClockSkewSeconds = normalizeAllowedClockSkewSeconds(options.allowedClockSkewSeconds);
  const ivTimestampSeconds = ivBuffer.readUInt32BE(8);
  const clockSkewSeconds = Math.abs(currentTimestampSeconds - ivTimestampSeconds);

  if (clockSkewSeconds > allowedClockSkewSeconds) {
    throw new Error("Incoming TLV payload contains encryptedMessage but iv timestamp is outside the allowed clock skew");
  }
}

function buildEncryptedMessageIv(options = {}) {
  if (options.iv) {
    const ivBuffer = Buffer.from(options.iv);
    if (ivBuffer.length !== 12) {
      throw new Error("Encrypted downlink iv is not 96 bits");
    }
    return ivBuffer;
  }

  const ivBuffer = crypto.randomBytes(12);
  const timestampSeconds = getCurrentTimestampSeconds(options);
  if (!Number.isFinite(timestampSeconds)) {
    throw new TypeError("currentTimestampSeconds must be a finite number");
  }
  ivBuffer.writeUInt32BE(timestampSeconds >>> 0, 8);
  return ivBuffer;
}

function buildAdditionalAuthenticatedData(message) {
  if (Buffer.isBuffer(message[TLV_AAD_SYMBOL])) {
    return message[TLV_AAD_SYMBOL];
  }

  const plaintextFields = { ...message };
  delete plaintextFields.encryptedMessage;
  delete plaintextFields.signature;
  return Buffer.from(encodeTlvPayload(plaintextFields, { direction: "uplink" }), "hex");
}

function getTlvAdditionalAuthenticatedData(message) {
  if (!Object.prototype.hasOwnProperty.call(message, "encryptedMessage")) {
    return null;
  }

  return buildAdditionalAuthenticatedData(message);
}

function decryptTlvUplinkMessage(message, key, options = {}) {
  if (!Object.prototype.hasOwnProperty.call(message, "encryptedMessage")) {
    return {
      payload: message,
      plaintext: null
    };
  }

  if (!message.iv) {
    throw new Error("Incoming TLV payload contains encryptedMessage but does not contain iv");
  }

  if (!Object.prototype.hasOwnProperty.call(message, "cryptoMode")) {
    throw new Error("Incoming TLV payload contains encryptedMessage but does not contain cryptoMode");
  }

  if (!isAes256PskCryptoMode(message.cryptoMode)) {
    throw new Error("Incoming TLV payload contains encryptedMessage but cryptoMode is not AES-256 (PSK)");
  }

  if (!message.signature) {
    throw new Error("Incoming TLV payload contains encryptedMessage but does not contain signature");
  }

  const algorithm = options.algorithm || "aes-256-gcm";
  const ivBuffer = Buffer.from(message.iv);
  validateEncryptedMessageIv(message, ivBuffer, options);
  const encryptedBuffer = Buffer.from(message.encryptedMessage);
  const authTagBuffer = Buffer.from(message.signature);

  const keyBuffer = normalizeEncryptionKey(key);

  if (authTagBuffer.length !== 16) {
    throw new Error("Incoming TLV payload contains encryptedMessage but signature is not a 16-byte AES-GCM auth tag");
  }

  const decipher = crypto.createDecipheriv(algorithm, keyBuffer, ivBuffer);
  decipher.setAAD(buildAdditionalAuthenticatedData(message));
  decipher.setAuthTag(authTagBuffer);

  const decryptedBuffer = Buffer.concat([
    decipher.update(encryptedBuffer),
    decipher.final()
  ]);

  const decryptedFields = decryptedBuffer.length === 0
    ? {}
    : parseTlvPayload(decryptedBuffer, { direction: "uplink" });
  const payload = {
    ...message,
    ...decryptedFields
  };
  delete payload.encryptedMessage;
  delete payload.signature;

  return {
    payload,
    plaintext: decryptedBuffer.toString("hex").toUpperCase()
  };
}
function normalizeCounterValue(value, fieldName) {
  const numericValue = Number(value);

  if (!Number.isInteger(numericValue) || numericValue < 0) {
    throw new TypeError(`${fieldName} must be a non-negative integer`);
  }

  return numericValue;
}

function normalizeDownlinkPayloadEntry(entry) {
  if (Buffer.isBuffer(entry)) {
    return Buffer.from(entry);
  }

  if (entry instanceof Uint8Array) {
    return Buffer.from(entry.buffer, entry.byteOffset, entry.byteLength);
  }

  if (entry instanceof ArrayBuffer) {
    return Buffer.from(entry);
  }

  if (typeof entry === "string") {
    const trimmed = entry.trim();
    if (isHexString(trimmed)) {
      return Buffer.from(trimmed, "hex");
    }
    return Buffer.from(entry, "utf8");
  }

  if (entry && typeof entry === "object") {
    return Buffer.from(JSON.stringify(entry), "utf8");
  }

  throw new TypeError("Downlink payloads must be Buffers, byte arrays, strings, or plain objects");
}

function normalizeDownlinkPayloads(downlinks) {
  if (downlinks === null || downlinks === undefined) {
    return [];
  }

  if (!Array.isArray(downlinks)) {
    throw new TypeError("Downlinks must be an array when provided");
  }

  return downlinks.map((entry) => normalizeDownlinkPayloadEntry(entry));
}

function formatDownlinkMessage({ uplinkAck, fCntDown, downlinks }) {
  const normalizedDownlinks = normalizeDownlinkPayloads(downlinks);
  const input = {
    ...(uplinkAck === null || uplinkAck === undefined
      ? {}
      : { uplinkAck: normalizeCounterValue(uplinkAck, "uplinkAck") }),
    ...(fCntDown === null || fCntDown === undefined
      ? {}
      : { fCntDown: normalizeCounterValue(fCntDown, "fCntDown") }),
    ...(normalizedDownlinks.length > 0
      ? { downlinks: normalizedDownlinks }
      : {})
  };
  const encoded = encodeTlvPayload(input, { direction: "downlink" });

  return Buffer.from(encoded, "hex");
}

function normalizeEncryptedDownlinkOptions(encryption) {
  if (!encryption) {
    return null;
  }

  if (!encryption.key) {
    throw new Error("Encrypted downlink requires an encryption key");
  }
  if (encryption.version === null || encryption.version === undefined) {
    throw new Error("Encrypted downlink requires version");
  }
  if (!encryption.stid) {
    throw new Error("Encrypted downlink requires stid");
  }

  return {
    algorithm: encryption.algorithm || "aes-256-gcm",
    key: normalizeEncryptionKey(encryption.key),
    version: normalizeCounterValue(encryption.version, "version"),
    stid: encryption.stid,
    iv: buildEncryptedMessageIv(encryption)
  };
}

function formatEncryptedDownlinkMessage({ uplinkAck, fCntDown, downlinks, encryption }) {
  const normalizedEncryption = normalizeEncryptedDownlinkOptions(encryption);
  if (!normalizedEncryption) {
    return formatDownlinkMessage({ uplinkAck, fCntDown, downlinks });
  }

  const plaintext = formatDownlinkMessage({ uplinkAck, fCntDown, downlinks });
  const authenticatedFields = {
    version: normalizedEncryption.version,
    stid: normalizedEncryption.stid,
    iv: normalizedEncryption.iv,
    cryptoMode: 1
  };
  const aad = Buffer.from(
    encodeTlvPayload(authenticatedFields, { direction: "downlink" }),
    "hex"
  );
  const cipher = crypto.createCipheriv(
    normalizedEncryption.algorithm,
    normalizedEncryption.key,
    normalizedEncryption.iv
  );
  cipher.setAAD(aad);
  const encryptedMessage = Buffer.concat([
    cipher.update(plaintext),
    cipher.final()
  ]);
  const signature = cipher.getAuthTag();

  return Buffer.from(
    encodeTlvPayload({
      ...authenticatedFields,
      signature,
      encryptedMessage
    }, { direction: "downlink" }),
    "hex"
  );
}

module.exports = {
  encodeTlvPayload,
  parseTlvPayload,
  getTlvBlocks,
  isHexString,
  parseTlvUplinkMessage,
  decryptTlvUplinkMessage,
  getTlvAdditionalAuthenticatedData,
  getTlvDeviceId,
  buildTlvMetadata,
  formatDownlinkMessage,
  formatEncryptedDownlinkMessage
};
