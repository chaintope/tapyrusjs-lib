'use strict';
// Container encoding of TIP-0174:
//
//   <pstt>       := <magic> <global-map> <input-map>* <output-map>*
//   <magic>      := 0x70 0x73 0x74 0x74 0xFF
//   <map>        := <keypair>* 0x00
//   <keypair>    := <key> <value>
//   <key>        := <keylen> <keytype> <keydata>
//   <value>      := <valuelen> <valuedata>
//
// This module knows nothing about the meaning of the records; it only turns the
// binary format into a list of records per map and back.
Object.defineProperty(exports, '__esModule', { value: true });
exports.recordKey = recordKey;
exports.encodeRecord = encodeRecord;
exports.decode = decode;
exports.encode = encode;
exports.encodeCompactSize = encodeCompactSize;
const bufferutils_1 = require('../bufferutils');
const fields_1 = require('./fields');
const varuint = require('varuint-bitcoin');
/**
 * The complete key of a record (`<keytype>` and `<keydata>`) as a string, for
 * the uniqueness rule of a map and for the deduplication a Combiner performs.
 * Both must agree on what "the same key" means, so there is one definition.
 */
function recordKey(record) {
  return record.type.toString(16) + ':' + record.keydata.toString('hex');
}
/**
 * Reader for the compact size unsigned integers and byte slices of the format.
 * Every compact size integer must be minimally encoded.
 */
class Reader {
  constructor(buffer, offset = 0) {
    this.buffer = buffer;
    this.offset = offset;
  }
  get eof() {
    return this.offset >= this.buffer.length;
  }
  peekUInt8() {
    if (this.eof) throw new Error('PSTT is truncated');
    return this.buffer[this.offset];
  }
  readCompactSize() {
    if (this.eof) throw new Error('PSTT is truncated');
    const first = this.buffer[this.offset];
    let value;
    let size;
    if (first < 0xfd) {
      value = first;
      size = 1;
    } else if (first === 0xfd) {
      this.checkAvailable(3);
      value = this.buffer.readUInt16LE(this.offset + 1);
      size = 3;
      if (value < 0xfd)
        throw new Error('Compact size is not minimally encoded');
    } else if (first === 0xfe) {
      this.checkAvailable(5);
      value = this.buffer.readUInt32LE(this.offset + 1);
      size = 5;
      if (value <= 0xffff)
        throw new Error('Compact size is not minimally encoded');
    } else {
      this.checkAvailable(9);
      value = (0, bufferutils_1.readUInt64LE)(this.buffer, this.offset + 1);
      size = 9;
      if (value <= 0xffffffff)
        throw new Error('Compact size is not minimally encoded');
    }
    this.offset += size;
    return value;
  }
  readSlice(n) {
    this.checkAvailable(n);
    const slice = this.buffer.subarray(this.offset, this.offset + n);
    this.offset += n;
    return slice;
  }
  checkAvailable(n) {
    if (this.offset + n > this.buffer.length)
      throw new Error('PSTT is truncated');
  }
}
function encodeCompactSize(value) {
  const buffer = Buffer.allocUnsafe(varuint.encodingLength(value));
  varuint.encode(value, buffer, 0);
  return buffer;
}
/**
 * Serialize one record as <keylen> <keytype> <keydata> <valuelen> <valuedata>.
 */
function encodeRecord(record) {
  const type = encodeCompactSize(record.type);
  return Buffer.concat([
    encodeCompactSize(type.length + record.keydata.length),
    type,
    record.keydata,
    encodeCompactSize(record.value.length),
    record.value,
  ]);
}
function encodeMap(records) {
  return Buffer.concat([
    ...records.map(encodeRecord),
    Buffer.from([0x00]), // map separator
  ]);
}
function decodeMap(reader) {
  const records = [];
  const seen = new Set();
  for (;;) {
    if (reader.eof) throw new Error('PSTT map is not terminated');
    if (reader.peekUInt8() === 0x00) {
      reader.offset += 1;
      return records;
    }
    const keyLength = reader.readCompactSize();
    const keyStart = reader.offset;
    const type = reader.readCompactSize();
    const typeLength = reader.offset - keyStart;
    if (typeLength > keyLength)
      throw new Error('PSTT keytype exceeds the declared key length');
    const keydata = reader.readSlice(keyLength - typeLength);
    const record = {
      type,
      keydata,
      value: reader.readSlice(reader.readCompactSize()),
    };
    const completeKey = recordKey(record);
    if (seen.has(completeKey))
      throw new Error(`Duplicate key 0x${type.toString(16)} in a PSTT map`);
    seen.add(completeKey);
    records.push(record);
  }
}
function readMapCount(global, type, name) {
  const record = global.find(r => r.type === type);
  if (record === undefined) throw new Error(`Missing ${name}`);
  const reader = new Reader(record.value);
  const count = reader.readCompactSize();
  if (!reader.eof) throw new Error(`${name} has trailing data`);
  return count;
}
/**
 * Split the raw byte stream into the global map and one map per input/output.
 */
function decode(buffer) {
  const reader = new Reader(buffer);
  if (!reader.readSlice(fields_1.MAGIC.length).equals(fields_1.MAGIC))
    throw new Error('Not a PSTT: magic bytes do not match');
  const maps = [];
  while (!reader.eof) maps.push(decodeMap(reader));
  if (maps.length === 0) throw new Error('Missing the PSTT global map');
  const global = maps[0];
  const inputCount = readMapCount(
    global,
    fields_1.GlobalTypes.INPUT_COUNT,
    'PSTT_GLOBAL_INPUT_COUNT',
  );
  const outputCount = readMapCount(
    global,
    fields_1.GlobalTypes.OUTPUT_COUNT,
    'PSTT_GLOBAL_OUTPUT_COUNT',
  );
  if (maps.length !== 1 + inputCount + outputCount)
    throw new Error(
      'The number of PSTT maps does not match ' +
        'PSTT_GLOBAL_INPUT_COUNT/PSTT_GLOBAL_OUTPUT_COUNT',
    );
  return {
    global,
    inputs: maps.slice(1, 1 + inputCount),
    outputs: maps.slice(1 + inputCount),
  };
}
function encode(raw) {
  return Buffer.concat([
    fields_1.MAGIC,
    encodeMap(raw.global),
    ...raw.inputs.map(encodeMap),
    ...raw.outputs.map(encodeMap),
  ]);
}
