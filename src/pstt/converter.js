'use strict';
// Conversion between the raw records of the PSTT container and the typed
// field structures, together with the static validation rules of TIP-0174:
// required fields, reserved type values, key data lengths and locktime bounds.
Object.defineProperty(exports, '__esModule', { value: true });
exports.fromRaw = fromRaw;
exports.toRaw = toRaw;
exports.decodeDerivationPath = decodeDerivationPath;
exports.encodeDerivationPath = encodeDerivationPath;
const bufferutils_1 = require('../bufferutils');
const container_1 = require('./container');
const fields_1 = require('./fields');
const HIGHEST_BIT = 0x80000000;
const XPUB_LENGTH = 78;
function find(records, type) {
  return records.find(r => r.type === type);
}
function filter(records, type) {
  return records.filter(r => r.type === type);
}
function readUInt32(record, name) {
  if (record.value.length !== 4)
    throw new Error(`${name} must be a 4-byte value`);
  return record.value.readUInt32LE(0);
}
/**
 * The value of an optional 32-bit little endian field, or undefined when the
 * record is absent.
 */
function optionalUInt32(records, type, name) {
  const record = find(records, type);
  return record && readUInt32(record, name);
}
/**
 * The value of an optional record, or undefined when the record is absent.
 */
function optionalValue(records, type) {
  const record = find(records, type);
  return record && record.value;
}
/**
 * Append a record only when the field it carries is set, so that an omitted
 * optional field produces no record at all.
 */
function pushOptional(records, type, value) {
  if (value !== undefined)
    records.push({ type, keydata: Buffer.alloc(0), value });
}
function push(records, type, value) {
  records.push({ type, keydata: Buffer.alloc(0), value });
}
function optionalUInt32Value(value) {
  return value === undefined ? undefined : writeUInt32(value);
}
function readInt32(record, name) {
  if (record.value.length !== 4)
    throw new Error(`${name} must be a 4-byte value`);
  return record.value.readInt32LE(0);
}
function writeUInt32(value) {
  const buffer = Buffer.allocUnsafe(4);
  buffer.writeUInt32LE(value, 0);
  return buffer;
}
function writeInt32(value) {
  const buffer = Buffer.allocUnsafe(4);
  buffer.writeInt32LE(value, 0);
  return buffer;
}
function readAmount(record, name) {
  if (record.value.length !== 8)
    throw new Error(`${name} must be an 8-byte value`);
  return (0, bufferutils_1.readUInt64LE)(record.value, 0);
}
function writeAmount(value) {
  const buffer = Buffer.allocUnsafe(8);
  (0, bufferutils_1.writeUInt64LE)(buffer, value, 0);
  return buffer;
}
function decodeDerivationPath(value, name) {
  if (value.length < 4 || value.length % 4 !== 0)
    throw new Error(`${name} must be a fingerprint followed by 32-bit indexes`);
  let path = 'm';
  for (let i = 4; i < value.length; i += 4) {
    const index = value.readUInt32LE(i);
    path +=
      '/' + (index & HIGHEST_BIT ? `${index & ~HIGHEST_BIT}'` : `${index}`);
  }
  return { masterFingerprint: value.subarray(0, 4), path };
}
function encodeDerivationPath(masterFingerprint, path) {
  const elements = path.split('/');
  if (elements[0] !== 'm') throw new Error(`Invalid derivation path ${path}`);
  const buffer = Buffer.allocUnsafe(4 + (elements.length - 1) * 4);
  masterFingerprint.copy(buffer, 0);
  elements.slice(1).forEach((element, i) => {
    const hardened = element.endsWith("'") || element.endsWith('h');
    const index = parseInt(hardened ? element.slice(0, -1) : element, 10);
    if (!(index >= 0 && index < HIGHEST_BIT))
      throw new Error(`Invalid derivation path ${path}`);
    buffer.writeUInt32LE(
      (hardened ? index | HIGHEST_BIT : index) >>> 0,
      4 + i * 4,
    );
  });
  return buffer;
}
function checkEmptyKeydata(records, types) {
  for (const record of records) {
    if (types.indexOf(record.type) !== -1 && record.keydata.length !== 0)
      throw new Error(
        `Type 0x${record.type.toString(16)} must have empty key data`,
      );
  }
}
function checkReserved(records, types, mapName) {
  for (const type of types) {
    if (find(records, type))
      throw new Error(
        `Reserved ${mapName} type 0x${type.toString(16)} must not be used`,
      );
  }
}
function checkPubkeyKeydata(record, name) {
  if (!(0, fields_1.isValidPubkeyLength)(record.keydata))
    throw new Error(`${name} key data must be a 33- or 65-byte public key`);
  return record.keydata;
}
function checkHashKeydata(record, length, name) {
  if (record.keydata.length !== length)
    throw new Error(`${name} key data must be a ${length}-byte hash`);
  return record.keydata;
}
function preimagesFromRecords(records, type, hashLength, name) {
  const preimages = {};
  for (const record of filter(records, type)) {
    preimages[checkHashKeydata(record, hashLength, name).toString('hex')] =
      record.value;
  }
  return preimages;
}
function preimagesToRecords(preimages, type) {
  return Object.keys(preimages).map(hash => ({
    type,
    keydata: Buffer.from(hash, 'hex'),
    value: preimages[hash],
  }));
}
function derivationsFromRecords(records, type, name) {
  return filter(records, type).map(record =>
    Object.assign(
      { pubkey: checkPubkeyKeydata(record, name) },
      decodeDerivationPath(record.value, name),
    ),
  );
}
function derivationsToRecords(derivations, type) {
  return derivations.map(derivation => ({
    type,
    keydata: derivation.pubkey,
    value: encodeDerivationPath(derivation.masterFingerprint, derivation.path),
  }));
}
function unknownFromRecords(records, known) {
  return records.filter(record => known.indexOf(record.type) === -1);
}
/**
 * The complete keys of a parsed map, kept so that the map can be written back
 * in the order it was read in.
 */
function orderOf(records) {
  return records.map(container_1.recordKey);
}
/**
 * Put the generated records of a map back into the order the map was parsed
 * in, so that parsing a PSTT and serializing it again yields the same bytes.
 * TIP-0174 prescribes no order — either order is a valid PSTT carrying the same
 * information — but a byte-stable round trip lets a caller hash, cache or diff
 * a PSTT without normalizing it first.
 *
 * A record that was not in the parsed map, such as a signature collected since,
 * has no place in that order; those keep the order this module generates them
 * in and follow the records that do.
 */
function inRecordOrder(records, order) {
  if (!order || order.length === 0) return records;
  const rank = {};
  order.forEach((key, i) => {
    if (rank[key] === undefined) rank[key] = i;
  });
  return records
    .map((record, i) => {
      const known = rank[(0, container_1.recordKey)(record)];
      return {
        record,
        rank: known === undefined ? order.length + i : known,
        i,
      };
    })
    .sort((a, b) => a.rank - b.rank || a.i - b.i)
    .map(entry => entry.record);
}
const KNOWN_GLOBAL_TYPES = [
  fields_1.GlobalTypes.XPUB,
  fields_1.GlobalTypes.TX_FEATURES,
  fields_1.GlobalTypes.FALLBACK_LOCKTIME,
  fields_1.GlobalTypes.INPUT_COUNT,
  fields_1.GlobalTypes.OUTPUT_COUNT,
  fields_1.GlobalTypes.TX_MODIFIABLE,
  fields_1.GlobalTypes.VERSION,
];
const KNOWN_INPUT_TYPES = [
  fields_1.InputTypes.UTXO,
  fields_1.InputTypes.PARTIAL_SIG,
  fields_1.InputTypes.SIGHASH_TYPE,
  fields_1.InputTypes.REDEEM_SCRIPT,
  fields_1.InputTypes.BIP32_DERIVATION,
  fields_1.InputTypes.FINAL_SCRIPTSIG,
  fields_1.InputTypes.RIPEMD160,
  fields_1.InputTypes.SHA256,
  fields_1.InputTypes.HASH160,
  fields_1.InputTypes.HASH256,
  fields_1.InputTypes.PREVIOUS_TXID,
  fields_1.InputTypes.OUTPUT_INDEX,
  fields_1.InputTypes.SEQUENCE,
  fields_1.InputTypes.REQUIRED_TIME_LOCKTIME,
  fields_1.InputTypes.REQUIRED_HEIGHT_LOCKTIME,
];
const KNOWN_OUTPUT_TYPES = [
  fields_1.OutputTypes.REDEEM_SCRIPT,
  fields_1.OutputTypes.BIP32_DERIVATION,
  fields_1.OutputTypes.AMOUNT,
  fields_1.OutputTypes.SCRIPT,
];
function globalFromRecords(records) {
  checkReserved(records, fields_1.RESERVED_GLOBAL_TYPES, 'global');
  checkEmptyKeydata(records, fields_1.EMPTY_KEYDATA_GLOBAL_TYPES);
  const versionRecord = find(records, fields_1.GlobalTypes.VERSION);
  const version =
    versionRecord && readUInt32(versionRecord, 'PSTT_GLOBAL_VERSION');
  if (version !== undefined && version > fields_1.PSTT_VERSION)
    throw new Error(`Unsupported PSTT version ${version}`);
  const featuresRecord = find(records, fields_1.GlobalTypes.TX_FEATURES);
  if (!featuresRecord) throw new Error('Missing PSTT_GLOBAL_TX_FEATURES');
  const txModifiableRecord = find(records, fields_1.GlobalTypes.TX_MODIFIABLE);
  if (txModifiableRecord && txModifiableRecord.value.length !== 1)
    throw new Error('PSTT_GLOBAL_TX_MODIFIABLE must be a 1-byte value');
  const xpub = filter(records, fields_1.GlobalTypes.XPUB).map(record => {
    if (record.keydata.length !== XPUB_LENGTH)
      throw new Error(
        `PSTT_GLOBAL_XPUB key data must be a ${XPUB_LENGTH}-byte extended public key`,
      );
    return Object.assign(
      { extendedPubkey: record.keydata },
      decodeDerivationPath(record.value, 'PSTT_GLOBAL_XPUB'),
    );
  });
  return {
    xpub,
    features: readInt32(featuresRecord, 'PSTT_GLOBAL_TX_FEATURES'),
    fallbackLocktime: optionalUInt32(
      records,
      fields_1.GlobalTypes.FALLBACK_LOCKTIME,
      'PSTT_GLOBAL_FALLBACK_LOCKTIME',
    ),
    txModifiable: txModifiableRecord && txModifiableRecord.value[0],
    version,
    unknownKeyVals: unknownFromRecords(records, [
      ...KNOWN_GLOBAL_TYPES,
      fields_1.GlobalTypes.INPUT_COUNT,
      fields_1.GlobalTypes.OUTPUT_COUNT,
    ]),
    recordOrder: orderOf(records),
  };
}
function globalToRecords(global, inputCount, outputCount) {
  const records = [];
  for (const xpub of global.xpub) {
    records.push({
      type: fields_1.GlobalTypes.XPUB,
      keydata: xpub.extendedPubkey,
      value: encodeDerivationPath(xpub.masterFingerprint, xpub.path),
    });
  }
  push(records, fields_1.GlobalTypes.TX_FEATURES, writeInt32(global.features));
  pushOptional(
    records,
    fields_1.GlobalTypes.FALLBACK_LOCKTIME,
    optionalUInt32Value(global.fallbackLocktime),
  );
  push(
    records,
    fields_1.GlobalTypes.INPUT_COUNT,
    (0, container_1.encodeCompactSize)(inputCount),
  );
  push(
    records,
    fields_1.GlobalTypes.OUTPUT_COUNT,
    (0, container_1.encodeCompactSize)(outputCount),
  );
  pushOptional(
    records,
    fields_1.GlobalTypes.TX_MODIFIABLE,
    global.txModifiable === undefined
      ? undefined
      : Buffer.from([global.txModifiable]),
  );
  pushOptional(
    records,
    fields_1.GlobalTypes.VERSION,
    optionalUInt32Value(global.version),
  );
  return inRecordOrder(
    records.concat(global.unknownKeyVals),
    global.recordOrder,
  );
}
function inputFromRecords(records) {
  checkReserved(records, fields_1.RESERVED_INPUT_TYPES, 'input');
  checkEmptyKeydata(records, fields_1.EMPTY_KEYDATA_INPUT_TYPES);
  const previousTxidRecord = find(records, fields_1.InputTypes.PREVIOUS_TXID);
  if (!previousTxidRecord || previousTxidRecord.value.length !== 32)
    throw new Error('Missing or malformed PSTT_IN_PREVIOUS_TXID');
  const outputIndexRecord = find(records, fields_1.InputTypes.OUTPUT_INDEX);
  if (!outputIndexRecord) throw new Error('Missing PSTT_IN_OUTPUT_INDEX');
  const sighashType = optionalUInt32(
    records,
    fields_1.InputTypes.SIGHASH_TYPE,
    'PSTT_IN_SIGHASH_TYPE',
  );
  if (
    sighashType !== undefined &&
    !(0, fields_1.isValidSighashType)(sighashType)
  )
    throw new Error(`Invalid PSTT_IN_SIGHASH_TYPE ${sighashType}`);
  const requiredTimeLocktime = optionalUInt32(
    records,
    fields_1.InputTypes.REQUIRED_TIME_LOCKTIME,
    'PSTT_IN_REQUIRED_TIME_LOCKTIME',
  );
  if (
    requiredTimeLocktime !== undefined &&
    requiredTimeLocktime < fields_1.LOCKTIME_THRESHOLD
  )
    throw new Error(
      `PSTT_IN_REQUIRED_TIME_LOCKTIME must be at least ${
        fields_1.LOCKTIME_THRESHOLD
      }`,
    );
  const requiredHeightLocktime = optionalUInt32(
    records,
    fields_1.InputTypes.REQUIRED_HEIGHT_LOCKTIME,
    'PSTT_IN_REQUIRED_HEIGHT_LOCKTIME',
  );
  if (
    requiredHeightLocktime !== undefined &&
    (requiredHeightLocktime === 0 ||
      requiredHeightLocktime >= fields_1.LOCKTIME_THRESHOLD)
  )
    throw new Error(
      `PSTT_IN_REQUIRED_HEIGHT_LOCKTIME must be greater than 0 and less than ${
        fields_1.LOCKTIME_THRESHOLD
      }`,
    );
  return {
    utxo: optionalValue(records, fields_1.InputTypes.UTXO),
    partialSig: filter(records, fields_1.InputTypes.PARTIAL_SIG).map(
      record => ({
        pubkey: checkPubkeyKeydata(record, 'PSTT_IN_PARTIAL_SIG'),
        signature: record.value,
      }),
    ),
    sighashType,
    redeemScript: optionalValue(records, fields_1.InputTypes.REDEEM_SCRIPT),
    bip32Derivation: derivationsFromRecords(
      records,
      fields_1.InputTypes.BIP32_DERIVATION,
      'PSTT_IN_BIP32_DERIVATION',
    ),
    finalScriptSig: optionalValue(records, fields_1.InputTypes.FINAL_SCRIPTSIG),
    ripemd160Preimages: preimagesFromRecords(
      records,
      fields_1.InputTypes.RIPEMD160,
      20,
      'PSTT_IN_RIPEMD160',
    ),
    sha256Preimages: preimagesFromRecords(
      records,
      fields_1.InputTypes.SHA256,
      32,
      'PSTT_IN_SHA256',
    ),
    hash160Preimages: preimagesFromRecords(
      records,
      fields_1.InputTypes.HASH160,
      20,
      'PSTT_IN_HASH160',
    ),
    hash256Preimages: preimagesFromRecords(
      records,
      fields_1.InputTypes.HASH256,
      32,
      'PSTT_IN_HASH256',
    ),
    previousTxid: previousTxidRecord.value,
    outputIndex: readUInt32(outputIndexRecord, 'PSTT_IN_OUTPUT_INDEX'),
    sequence: optionalUInt32(
      records,
      fields_1.InputTypes.SEQUENCE,
      'PSTT_IN_SEQUENCE',
    ),
    requiredTimeLocktime,
    requiredHeightLocktime,
    unknownKeyVals: unknownFromRecords(records, KNOWN_INPUT_TYPES),
    recordOrder: orderOf(records),
  };
}
function inputToRecords(input) {
  const records = [];
  pushOptional(records, fields_1.InputTypes.UTXO, input.utxo);
  for (const sig of input.partialSig) {
    records.push({
      type: fields_1.InputTypes.PARTIAL_SIG,
      keydata: sig.pubkey,
      value: sig.signature,
    });
  }
  pushOptional(
    records,
    fields_1.InputTypes.SIGHASH_TYPE,
    optionalUInt32Value(input.sighashType),
  );
  pushOptional(records, fields_1.InputTypes.REDEEM_SCRIPT, input.redeemScript);
  records.push(
    ...derivationsToRecords(
      input.bip32Derivation,
      fields_1.InputTypes.BIP32_DERIVATION,
    ),
  );
  pushOptional(
    records,
    fields_1.InputTypes.FINAL_SCRIPTSIG,
    input.finalScriptSig,
  );
  records.push(
    ...preimagesToRecords(
      input.ripemd160Preimages,
      fields_1.InputTypes.RIPEMD160,
    ),
    ...preimagesToRecords(input.sha256Preimages, fields_1.InputTypes.SHA256),
    ...preimagesToRecords(input.hash160Preimages, fields_1.InputTypes.HASH160),
    ...preimagesToRecords(input.hash256Preimages, fields_1.InputTypes.HASH256),
  );
  push(records, fields_1.InputTypes.PREVIOUS_TXID, input.previousTxid);
  push(
    records,
    fields_1.InputTypes.OUTPUT_INDEX,
    writeUInt32(input.outputIndex),
  );
  pushOptional(
    records,
    fields_1.InputTypes.SEQUENCE,
    optionalUInt32Value(input.sequence),
  );
  pushOptional(
    records,
    fields_1.InputTypes.REQUIRED_TIME_LOCKTIME,
    optionalUInt32Value(input.requiredTimeLocktime),
  );
  pushOptional(
    records,
    fields_1.InputTypes.REQUIRED_HEIGHT_LOCKTIME,
    optionalUInt32Value(input.requiredHeightLocktime),
  );
  return inRecordOrder(records.concat(input.unknownKeyVals), input.recordOrder);
}
function outputFromRecords(records) {
  checkReserved(records, fields_1.RESERVED_OUTPUT_TYPES, 'output');
  checkEmptyKeydata(records, fields_1.EMPTY_KEYDATA_OUTPUT_TYPES);
  const amountRecord = find(records, fields_1.OutputTypes.AMOUNT);
  if (!amountRecord) throw new Error('Missing PSTT_OUT_AMOUNT');
  const scriptRecord = find(records, fields_1.OutputTypes.SCRIPT);
  if (!scriptRecord) throw new Error('Missing PSTT_OUT_SCRIPT');
  return {
    redeemScript: optionalValue(records, fields_1.OutputTypes.REDEEM_SCRIPT),
    bip32Derivation: derivationsFromRecords(
      records,
      fields_1.OutputTypes.BIP32_DERIVATION,
      'PSTT_OUT_BIP32_DERIVATION',
    ),
    amount: readAmount(amountRecord, 'PSTT_OUT_AMOUNT'),
    script: scriptRecord.value,
    unknownKeyVals: unknownFromRecords(records, KNOWN_OUTPUT_TYPES),
    recordOrder: orderOf(records),
  };
}
function outputToRecords(output) {
  const records = [];
  pushOptional(
    records,
    fields_1.OutputTypes.REDEEM_SCRIPT,
    output.redeemScript,
  );
  records.push(
    ...derivationsToRecords(
      output.bip32Derivation,
      fields_1.OutputTypes.BIP32_DERIVATION,
    ),
  );
  push(records, fields_1.OutputTypes.AMOUNT, writeAmount(output.amount));
  push(records, fields_1.OutputTypes.SCRIPT, output.script);
  return inRecordOrder(
    records.concat(output.unknownKeyVals),
    output.recordOrder,
  );
}
function fromRaw(raw) {
  return {
    global: globalFromRecords(raw.global),
    inputs: raw.inputs.map(inputFromRecords),
    outputs: raw.outputs.map(outputFromRecords),
  };
}
function toRaw(data) {
  return {
    global: globalToRecords(
      data.global,
      data.inputs.length,
      data.outputs.length,
    ),
    inputs: data.inputs.map(inputToRecords),
    outputs: data.outputs.map(outputToRecords),
  };
}
