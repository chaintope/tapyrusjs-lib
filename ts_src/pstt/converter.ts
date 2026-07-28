// Conversion between the raw records of the PSTT container and the typed
// field structures, together with the static validation rules of TIP-0174:
// required fields, reserved type values, key data lengths and locktime bounds.

import { readUInt64LE, writeUInt64LE } from '../bufferutils';
import { encodeCompactSize, PsttRecord, RawPstt, recordKey } from './container';
import {
  EMPTY_KEYDATA_GLOBAL_TYPES,
  EMPTY_KEYDATA_INPUT_TYPES,
  EMPTY_KEYDATA_OUTPUT_TYPES,
  GlobalTypes,
  InputTypes,
  isValidPubkeyLength,
  isValidSighashType,
  isValidTxModifiable,
  LOCKTIME_THRESHOLD,
  OutputTypes,
  PSTT_VERSION,
  RESERVED_GLOBAL_TYPES,
  RESERVED_INPUT_TYPES,
  RESERVED_OUTPUT_TYPES,
} from './fields';
import {
  Bip32Derivation,
  PreimageMap,
  PsttGlobal,
  PsttInput,
  PsttOutput,
  RecordOrder,
} from './interfaces';

const HIGHEST_BIT = 0x80000000;
const XPUB_LENGTH = 78;

function find(records: PsttRecord[], type: number): PsttRecord | undefined {
  return records.find(r => r.type === type);
}

function filter(records: PsttRecord[], type: number): PsttRecord[] {
  return records.filter(r => r.type === type);
}

function readUInt32(record: PsttRecord, name: string): number {
  if (record.value.length !== 4)
    throw new Error(`${name} must be a 4-byte value`);
  return record.value.readUInt32LE(0);
}

/**
 * The value of an optional 32-bit little endian field, or undefined when the
 * record is absent.
 */
function optionalUInt32(
  records: PsttRecord[],
  type: number,
  name: string,
): number | undefined {
  const record = find(records, type);
  return record && readUInt32(record, name);
}

/**
 * The value of an optional record, or undefined when the record is absent.
 */
function optionalValue(
  records: PsttRecord[],
  type: number,
): Buffer | undefined {
  const record = find(records, type);
  return record && record.value;
}

/**
 * Append a record only when the field it carries is set, so that an omitted
 * optional field produces no record at all.
 */
function pushOptional(
  records: PsttRecord[],
  type: number,
  value: Buffer | undefined,
): void {
  if (value !== undefined)
    records.push({ type, keydata: Buffer.alloc(0), value });
}

function push(records: PsttRecord[], type: number, value: Buffer): void {
  records.push({ type, keydata: Buffer.alloc(0), value });
}

function optionalUInt32Value(value: number | undefined): Buffer | undefined {
  return value === undefined ? undefined : writeUInt32(value);
}

function readInt32(record: PsttRecord, name: string): number {
  if (record.value.length !== 4)
    throw new Error(`${name} must be a 4-byte value`);
  return record.value.readInt32LE(0);
}

function writeUInt32(value: number): Buffer {
  const buffer = Buffer.allocUnsafe(4);
  buffer.writeUInt32LE(value, 0);
  return buffer;
}

function writeInt32(value: number): Buffer {
  const buffer = Buffer.allocUnsafe(4);
  buffer.writeInt32LE(value, 0);
  return buffer;
}

function readAmount(record: PsttRecord, name: string): number {
  if (record.value.length !== 8)
    throw new Error(`${name} must be an 8-byte value`);
  return readUInt64LE(record.value, 0);
}

function writeAmount(value: number): Buffer {
  const buffer = Buffer.allocUnsafe(8);
  writeUInt64LE(buffer, value, 0);
  return buffer;
}

function decodeDerivationPath(
  value: Buffer,
  name: string,
): { masterFingerprint: Buffer; path: string } {
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

function encodeDerivationPath(masterFingerprint: Buffer, path: string): Buffer {
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

function checkEmptyKeydata(records: PsttRecord[], types: number[]): void {
  for (const record of records) {
    if (types.indexOf(record.type) !== -1 && record.keydata.length !== 0)
      throw new Error(
        `Type 0x${record.type.toString(16)} must have empty key data`,
      );
  }
}

function checkReserved(
  records: PsttRecord[],
  types: number[],
  mapName: string,
): void {
  for (const type of types) {
    if (find(records, type))
      throw new Error(
        `Reserved ${mapName} type 0x${type.toString(16)} must not be used`,
      );
  }
}

function checkPubkeyKeydata(record: PsttRecord, name: string): Buffer {
  if (!isValidPubkeyLength(record.keydata))
    throw new Error(`${name} key data must be a 33- or 65-byte public key`);
  return record.keydata;
}

function checkHashKeydata(
  record: PsttRecord,
  length: number,
  name: string,
): Buffer {
  if (record.keydata.length !== length)
    throw new Error(`${name} key data must be a ${length}-byte hash`);
  return record.keydata;
}

function preimagesFromRecords(
  records: PsttRecord[],
  type: number,
  hashLength: number,
  name: string,
): PreimageMap {
  const preimages: PreimageMap = {};
  for (const record of filter(records, type)) {
    preimages[checkHashKeydata(record, hashLength, name).toString('hex')] =
      record.value;
  }
  return preimages;
}

function preimagesToRecords(
  preimages: PreimageMap,
  type: number,
): PsttRecord[] {
  return Object.keys(preimages).map(hash => ({
    type,
    keydata: Buffer.from(hash, 'hex'),
    value: preimages[hash],
  }));
}

function derivationsFromRecords(
  records: PsttRecord[],
  type: number,
  name: string,
): Bip32Derivation[] {
  return filter(records, type).map(record => ({
    pubkey: checkPubkeyKeydata(record, name),
    ...decodeDerivationPath(record.value, name),
  }));
}

function derivationsToRecords(
  derivations: Bip32Derivation[],
  type: number,
): PsttRecord[] {
  return derivations.map(derivation => ({
    type,
    keydata: derivation.pubkey,
    value: encodeDerivationPath(derivation.masterFingerprint, derivation.path),
  }));
}

function unknownFromRecords(
  records: PsttRecord[],
  known: number[],
): PsttRecord[] {
  return records.filter(record => known.indexOf(record.type) === -1);
}

/**
 * The complete keys of a parsed map, kept so that the map can be written back
 * in the order it was read in.
 */
function orderOf(records: PsttRecord[]): RecordOrder {
  return records.map(recordKey);
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
function inRecordOrder(
  records: PsttRecord[],
  order?: RecordOrder,
): PsttRecord[] {
  if (!order || order.length === 0) return records;

  const rank: { [key: string]: number } = {};
  order.forEach((key, i) => {
    if (rank[key] === undefined) rank[key] = i;
  });

  return records
    .map((record, i) => {
      const known = rank[recordKey(record)];
      return {
        record,
        rank: known === undefined ? order.length + i : known,
        i,
      };
    })
    .sort((a, b) => a.rank - b.rank || a.i - b.i)
    .map(entry => entry.record);
}

const KNOWN_GLOBAL_TYPES: number[] = [
  GlobalTypes.XPUB,
  GlobalTypes.TX_FEATURES,
  GlobalTypes.FALLBACK_LOCKTIME,
  GlobalTypes.INPUT_COUNT,
  GlobalTypes.OUTPUT_COUNT,
  GlobalTypes.TX_MODIFIABLE,
  GlobalTypes.VERSION,
];

const KNOWN_INPUT_TYPES: number[] = [
  InputTypes.UTXO,
  InputTypes.PARTIAL_SIG,
  InputTypes.SIGHASH_TYPE,
  InputTypes.REDEEM_SCRIPT,
  InputTypes.BIP32_DERIVATION,
  InputTypes.FINAL_SCRIPTSIG,
  InputTypes.RIPEMD160,
  InputTypes.SHA256,
  InputTypes.HASH160,
  InputTypes.HASH256,
  InputTypes.PREVIOUS_TXID,
  InputTypes.OUTPUT_INDEX,
  InputTypes.SEQUENCE,
  InputTypes.REQUIRED_TIME_LOCKTIME,
  InputTypes.REQUIRED_HEIGHT_LOCKTIME,
];

const KNOWN_OUTPUT_TYPES: number[] = [
  OutputTypes.REDEEM_SCRIPT,
  OutputTypes.BIP32_DERIVATION,
  OutputTypes.AMOUNT,
  OutputTypes.SCRIPT,
];

function globalFromRecords(records: PsttRecord[]): PsttGlobal {
  checkReserved(records, RESERVED_GLOBAL_TYPES, 'global');
  checkEmptyKeydata(records, EMPTY_KEYDATA_GLOBAL_TYPES);

  const versionRecord = find(records, GlobalTypes.VERSION);
  const version =
    versionRecord && readUInt32(versionRecord, 'PSTT_GLOBAL_VERSION');
  if (version !== undefined && version > PSTT_VERSION)
    throw new Error(`Unsupported PSTT version ${version}`);

  const featuresRecord = find(records, GlobalTypes.TX_FEATURES);
  if (!featuresRecord) throw new Error('Missing PSTT_GLOBAL_TX_FEATURES');

  const txModifiableRecord = find(records, GlobalTypes.TX_MODIFIABLE);
  if (txModifiableRecord) {
    if (txModifiableRecord.value.length !== 1)
      throw new Error('PSTT_GLOBAL_TX_MODIFIABLE must be a 1-byte value');
    if (!isValidTxModifiable(txModifiableRecord.value[0]))
      throw new Error(
        'PSTT_GLOBAL_TX_MODIFIABLE must leave the bits TIP-0174 reserves at 0',
      );
  }

  const xpub = filter(records, GlobalTypes.XPUB).map(record => {
    if (record.keydata.length !== XPUB_LENGTH)
      throw new Error(
        `PSTT_GLOBAL_XPUB key data must be a ${XPUB_LENGTH}-byte extended public key`,
      );
    return {
      extendedPubkey: record.keydata,
      ...decodeDerivationPath(record.value, 'PSTT_GLOBAL_XPUB'),
    };
  });

  return {
    xpub,
    features: readInt32(featuresRecord, 'PSTT_GLOBAL_TX_FEATURES'),
    fallbackLocktime: optionalUInt32(
      records,
      GlobalTypes.FALLBACK_LOCKTIME,
      'PSTT_GLOBAL_FALLBACK_LOCKTIME',
    ),
    txModifiable: txModifiableRecord && txModifiableRecord.value[0],
    version,
    unknownKeyVals: unknownFromRecords(records, [
      ...KNOWN_GLOBAL_TYPES,
      GlobalTypes.INPUT_COUNT,
      GlobalTypes.OUTPUT_COUNT,
    ]),
    recordOrder: orderOf(records),
  };
}

function globalToRecords(
  global: PsttGlobal,
  inputCount: number,
  outputCount: number,
): PsttRecord[] {
  const records: PsttRecord[] = [];

  for (const xpub of global.xpub) {
    records.push({
      type: GlobalTypes.XPUB,
      keydata: xpub.extendedPubkey,
      value: encodeDerivationPath(xpub.masterFingerprint, xpub.path),
    });
  }
  push(records, GlobalTypes.TX_FEATURES, writeInt32(global.features));
  pushOptional(
    records,
    GlobalTypes.FALLBACK_LOCKTIME,
    optionalUInt32Value(global.fallbackLocktime),
  );
  push(records, GlobalTypes.INPUT_COUNT, encodeCompactSize(inputCount));
  push(records, GlobalTypes.OUTPUT_COUNT, encodeCompactSize(outputCount));
  pushOptional(
    records,
    GlobalTypes.TX_MODIFIABLE,
    global.txModifiable === undefined
      ? undefined
      : Buffer.from([global.txModifiable]),
  );
  pushOptional(
    records,
    GlobalTypes.VERSION,
    optionalUInt32Value(global.version),
  );

  return inRecordOrder(
    records.concat(global.unknownKeyVals),
    global.recordOrder,
  );
}

function inputFromRecords(records: PsttRecord[]): PsttInput {
  checkReserved(records, RESERVED_INPUT_TYPES, 'input');
  checkEmptyKeydata(records, EMPTY_KEYDATA_INPUT_TYPES);

  const previousTxidRecord = find(records, InputTypes.PREVIOUS_TXID);
  if (!previousTxidRecord || previousTxidRecord.value.length !== 32)
    throw new Error('Missing or malformed PSTT_IN_PREVIOUS_TXID');

  const outputIndexRecord = find(records, InputTypes.OUTPUT_INDEX);
  if (!outputIndexRecord) throw new Error('Missing PSTT_IN_OUTPUT_INDEX');

  const sighashType = optionalUInt32(
    records,
    InputTypes.SIGHASH_TYPE,
    'PSTT_IN_SIGHASH_TYPE',
  );
  if (sighashType !== undefined && !isValidSighashType(sighashType))
    throw new Error(`Invalid PSTT_IN_SIGHASH_TYPE ${sighashType}`);

  const requiredTimeLocktime = optionalUInt32(
    records,
    InputTypes.REQUIRED_TIME_LOCKTIME,
    'PSTT_IN_REQUIRED_TIME_LOCKTIME',
  );
  if (
    requiredTimeLocktime !== undefined &&
    requiredTimeLocktime < LOCKTIME_THRESHOLD
  )
    throw new Error(
      `PSTT_IN_REQUIRED_TIME_LOCKTIME must be at least ${LOCKTIME_THRESHOLD}`,
    );

  const requiredHeightLocktime = optionalUInt32(
    records,
    InputTypes.REQUIRED_HEIGHT_LOCKTIME,
    'PSTT_IN_REQUIRED_HEIGHT_LOCKTIME',
  );
  if (
    requiredHeightLocktime !== undefined &&
    (requiredHeightLocktime === 0 ||
      requiredHeightLocktime >= LOCKTIME_THRESHOLD)
  )
    throw new Error(
      `PSTT_IN_REQUIRED_HEIGHT_LOCKTIME must be greater than 0 and less than ${LOCKTIME_THRESHOLD}`,
    );

  return {
    utxo: optionalValue(records, InputTypes.UTXO),
    partialSig: filter(records, InputTypes.PARTIAL_SIG).map(record => ({
      pubkey: checkPubkeyKeydata(record, 'PSTT_IN_PARTIAL_SIG'),
      signature: record.value,
    })),
    sighashType,
    redeemScript: optionalValue(records, InputTypes.REDEEM_SCRIPT),
    bip32Derivation: derivationsFromRecords(
      records,
      InputTypes.BIP32_DERIVATION,
      'PSTT_IN_BIP32_DERIVATION',
    ),
    finalScriptSig: optionalValue(records, InputTypes.FINAL_SCRIPTSIG),
    ripemd160Preimages: preimagesFromRecords(
      records,
      InputTypes.RIPEMD160,
      20,
      'PSTT_IN_RIPEMD160',
    ),
    sha256Preimages: preimagesFromRecords(
      records,
      InputTypes.SHA256,
      32,
      'PSTT_IN_SHA256',
    ),
    hash160Preimages: preimagesFromRecords(
      records,
      InputTypes.HASH160,
      20,
      'PSTT_IN_HASH160',
    ),
    hash256Preimages: preimagesFromRecords(
      records,
      InputTypes.HASH256,
      32,
      'PSTT_IN_HASH256',
    ),
    previousTxid: previousTxidRecord.value,
    outputIndex: readUInt32(outputIndexRecord, 'PSTT_IN_OUTPUT_INDEX'),
    sequence: optionalUInt32(records, InputTypes.SEQUENCE, 'PSTT_IN_SEQUENCE'),
    requiredTimeLocktime,
    requiredHeightLocktime,
    unknownKeyVals: unknownFromRecords(records, KNOWN_INPUT_TYPES),
    recordOrder: orderOf(records),
  };
}

function inputToRecords(input: PsttInput): PsttRecord[] {
  const records: PsttRecord[] = [];

  pushOptional(records, InputTypes.UTXO, input.utxo);
  for (const sig of input.partialSig) {
    records.push({
      type: InputTypes.PARTIAL_SIG,
      keydata: sig.pubkey,
      value: sig.signature,
    });
  }
  pushOptional(
    records,
    InputTypes.SIGHASH_TYPE,
    optionalUInt32Value(input.sighashType),
  );
  pushOptional(records, InputTypes.REDEEM_SCRIPT, input.redeemScript);
  records.push(
    ...derivationsToRecords(input.bip32Derivation, InputTypes.BIP32_DERIVATION),
  );
  pushOptional(records, InputTypes.FINAL_SCRIPTSIG, input.finalScriptSig);
  records.push(
    ...preimagesToRecords(input.ripemd160Preimages, InputTypes.RIPEMD160),
    ...preimagesToRecords(input.sha256Preimages, InputTypes.SHA256),
    ...preimagesToRecords(input.hash160Preimages, InputTypes.HASH160),
    ...preimagesToRecords(input.hash256Preimages, InputTypes.HASH256),
  );
  push(records, InputTypes.PREVIOUS_TXID, input.previousTxid);
  push(records, InputTypes.OUTPUT_INDEX, writeUInt32(input.outputIndex));
  pushOptional(
    records,
    InputTypes.SEQUENCE,
    optionalUInt32Value(input.sequence),
  );
  pushOptional(
    records,
    InputTypes.REQUIRED_TIME_LOCKTIME,
    optionalUInt32Value(input.requiredTimeLocktime),
  );
  pushOptional(
    records,
    InputTypes.REQUIRED_HEIGHT_LOCKTIME,
    optionalUInt32Value(input.requiredHeightLocktime),
  );

  return inRecordOrder(records.concat(input.unknownKeyVals), input.recordOrder);
}

function outputFromRecords(records: PsttRecord[]): PsttOutput {
  checkReserved(records, RESERVED_OUTPUT_TYPES, 'output');
  checkEmptyKeydata(records, EMPTY_KEYDATA_OUTPUT_TYPES);

  const amountRecord = find(records, OutputTypes.AMOUNT);
  if (!amountRecord) throw new Error('Missing PSTT_OUT_AMOUNT');

  const scriptRecord = find(records, OutputTypes.SCRIPT);
  if (!scriptRecord) throw new Error('Missing PSTT_OUT_SCRIPT');

  return {
    redeemScript: optionalValue(records, OutputTypes.REDEEM_SCRIPT),
    bip32Derivation: derivationsFromRecords(
      records,
      OutputTypes.BIP32_DERIVATION,
      'PSTT_OUT_BIP32_DERIVATION',
    ),
    amount: readAmount(amountRecord, 'PSTT_OUT_AMOUNT'),
    script: scriptRecord.value,
    unknownKeyVals: unknownFromRecords(records, KNOWN_OUTPUT_TYPES),
    recordOrder: orderOf(records),
  };
}

function outputToRecords(output: PsttOutput): PsttRecord[] {
  const records: PsttRecord[] = [];

  pushOptional(records, OutputTypes.REDEEM_SCRIPT, output.redeemScript);
  records.push(
    ...derivationsToRecords(
      output.bip32Derivation,
      OutputTypes.BIP32_DERIVATION,
    ),
  );
  push(records, OutputTypes.AMOUNT, writeAmount(output.amount));
  push(records, OutputTypes.SCRIPT, output.script);

  return inRecordOrder(
    records.concat(output.unknownKeyVals),
    output.recordOrder,
  );
}

export interface PsttData {
  global: PsttGlobal;
  inputs: PsttInput[];
  outputs: PsttOutput[];
}

export function fromRaw(raw: RawPstt): PsttData {
  return {
    global: globalFromRecords(raw.global),
    inputs: raw.inputs.map(inputFromRecords),
    outputs: raw.outputs.map(outputFromRecords),
  };
}

export function toRaw(data: PsttData): RawPstt {
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

export { decodeDerivationPath, encodeDerivationPath };
