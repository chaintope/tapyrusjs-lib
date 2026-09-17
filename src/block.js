'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.Block = exports.XFieldType = exports.PROOF_LENGTH = exports.BLOCK_FEATURES = void 0;
const bufferutils_1 = require('./bufferutils');
const bcrypto = require('./crypto');
const schnorr = require('./schnorr');
const transaction_1 = require('./transaction');
const types = require('./types');
const fastMerkleRoot = require('merkle-lib/fastRoot');
const typeforce = require('typeforce');
const varuint = require('varuint-bitcoin');
const errorMerkleNoTxes = new TypeError(
  'Cannot compute merkle root for zero transactions',
);
/** The only value nFeatures may take. */
exports.BLOCK_FEATURES = 1;
/** The length of the Schnorr signature a signed block carries. */
exports.PROOF_LENGTH = 64;
/**
 * The extension field of a block header. Its payload depends on the type, and
 * the two defined payloads are not encoded the same way: an aggregate public
 * key is a length-prefixed vector, while a maximum block size is four raw
 * bytes.
 */
var XFieldType;
(function(XFieldType) {
  XFieldType[(XFieldType['NONE'] = 0)] = 'NONE';
  XFieldType[(XFieldType['AGGREGATE_PUBKEY'] = 1)] = 'AGGREGATE_PUBKEY';
  XFieldType[(XFieldType['MAX_BLOCK_SIZE'] = 2)] = 'MAX_BLOCK_SIZE';
})(XFieldType || (exports.XFieldType = XFieldType = {}));
const AGGREGATE_PUBKEY_LENGTH = 33;
/**
 * features, prevHash, merkleRoot, imMerkleRoot and timestamp, plus an empty
 * xfield and an empty proof.
 */
const MIN_HEADER_LENGTH = 4 + 32 + 32 + 32 + 4 + 1 + 1;
function readXField(bufferReader) {
  const type = bufferReader.readUInt8();
  switch (type) {
    case XFieldType.NONE:
      // consumes no payload at all
      return { type: XFieldType.NONE };
    case XFieldType.AGGREGATE_PUBKEY: {
      const aggregatePubkey = bufferReader.readVarSlice();
      if (aggregatePubkey.length !== AGGREGATE_PUBKEY_LENGTH)
        throw new Error('Invalid aggregate public key in xfield');
      return { type: XFieldType.AGGREGATE_PUBKEY, aggregatePubkey };
    }
    case XFieldType.MAX_BLOCK_SIZE:
      // four raw bytes, with no length prefix
      return {
        type: XFieldType.MAX_BLOCK_SIZE,
        maxBlockSize: bufferReader.readUInt32(),
      };
    default:
      throw new Error(`Unknown xfield type ${type}`);
  }
}
function writeXField(bufferWriter, xfield) {
  bufferWriter.writeUInt8(xfield.type);
  switch (xfield.type) {
    case XFieldType.NONE:
      return;
    case XFieldType.AGGREGATE_PUBKEY:
      if (
        !xfield.aggregatePubkey ||
        xfield.aggregatePubkey.length !== AGGREGATE_PUBKEY_LENGTH
      )
        throw new Error('Invalid aggregate public key in xfield');
      bufferWriter.writeVarSlice(xfield.aggregatePubkey);
      return;
    case XFieldType.MAX_BLOCK_SIZE:
      if (xfield.maxBlockSize === undefined)
        throw new Error('Missing maximum block size in xfield');
      bufferWriter.writeUInt32(xfield.maxBlockSize);
      return;
    default:
      throw new Error(`Unknown xfield type ${xfield.type}`);
  }
}
function xfieldLength(xfield) {
  switch (xfield.type) {
    case XFieldType.NONE:
      return 1;
    case XFieldType.AGGREGATE_PUBKEY:
      return (
        1 +
        varuint.encodingLength(AGGREGATE_PUBKEY_LENGTH) +
        AGGREGATE_PUBKEY_LENGTH
      );
    case XFieldType.MAX_BLOCK_SIZE:
      return 1 + 4;
    default:
      throw new Error(`Unknown xfield type ${xfield.type}`);
  }
}
class Block {
  constructor() {
    this.features = exports.BLOCK_FEATURES;
    this.prevHash = undefined;
    this.merkleRoot = undefined;
    this.imMerkleRoot = undefined;
    this.timestamp = 0;
    this.xfield = { type: XFieldType.NONE };
    this.proof = Buffer.alloc(0);
    this.transactions = undefined;
  }
  static fromBuffer(buffer) {
    if (buffer.length < MIN_HEADER_LENGTH)
      throw new Error(`Buffer too small (< ${MIN_HEADER_LENGTH} bytes)`);
    const bufferReader = new bufferutils_1.BufferReader(buffer);
    const block = new Block();
    block.features = bufferReader.readInt32();
    block.prevHash = bufferReader.readSlice(32);
    block.merkleRoot = bufferReader.readSlice(32);
    block.imMerkleRoot = bufferReader.readSlice(32);
    block.timestamp = bufferReader.readUInt32();
    block.xfield = readXField(bufferReader);
    block.proof = bufferReader.readVarSlice();
    if (bufferReader.offset === buffer.length) return block;
    const readTransaction = () => {
      const tx = transaction_1.Transaction.fromBuffer(
        bufferReader.buffer.slice(bufferReader.offset),
        true,
      );
      bufferReader.offset += tx.byteLength();
      return tx;
    };
    const nTransactions = bufferReader.readVarInt();
    block.transactions = [];
    for (let i = 0; i < nTransactions; ++i) {
      block.transactions.push(readTransaction());
    }
    return block;
  }
  static fromHex(hex) {
    return Block.fromBuffer(Buffer.from(hex, 'hex'));
  }
  /**
   * The merkle root over the transaction hashes, which include the scriptSig
   * of every input. This is the `merkleRoot` of the header.
   */
  static calculateMerkleRoot(transactions) {
    typeforce([{ getHash: types.Function }], transactions);
    if (transactions.length === 0) throw errorMerkleNoTxes;
    const hashes = transactions.map(transaction => transaction.getHash());
    return fastMerkleRoot(hashes, bcrypto.hash256);
  }
  /**
   * The merkle root over the hashMalFix of the transactions, which omit the
   * scriptSig. This is the `imMerkleRoot` of the header, and it does not
   * change when a scriptSig is altered.
   */
  static calculateImMerkleRoot(transactions) {
    typeforce([{ getMalFixHash: types.Function }], transactions);
    if (transactions.length === 0) throw errorMerkleNoTxes;
    const hashes = transactions.map(transaction => transaction.getMalFixHash());
    return fastMerkleRoot(hashes, bcrypto.hash256);
  }
  byteLength(headersOnly) {
    return this.__byteLength(headersOnly, true);
  }
  /** The block identifier, over the whole header including the proof. */
  getHash() {
    return bcrypto.hash256(this.toBuffer(true));
  }
  getId() {
    return (0, bufferutils_1.reverseBuffer)(this.getHash()).toString('hex');
  }
  /** What the signer signs: the header without the proof. */
  getHashForSign() {
    return bcrypto.hash256(this.__toBuffer(true, false));
  }
  getUTCDate() {
    const date = new Date(0); // epoch
    date.setUTCSeconds(this.timestamp);
    return date;
  }
  toBuffer(headersOnly) {
    return this.__toBuffer(headersOnly, true);
  }
  toHex(headersOnly) {
    return this.toBuffer(headersOnly).toString('hex');
  }
  /** Both merkle roots of the header must match the transactions. */
  checkMerkleRoot() {
    if (!this.transactions) throw errorMerkleNoTxes;
    return (
      this.merkleRoot.equals(Block.calculateMerkleRoot(this.transactions)) &&
      this.imMerkleRoot.equals(Block.calculateImMerkleRoot(this.transactions))
    );
  }
  /**
   * Verify the block signature against the aggregate public key that was in
   * force at this height. The key is not stored in the library: it starts in
   * the genesis block and is replaced by later blocks through the xfield, so
   * the caller has to supply the one that applies.
   */
  checkProof(aggregatePubkey) {
    typeforce(types.Buffer, aggregatePubkey);
    if (this.features !== exports.BLOCK_FEATURES) return false;
    if (this.proof.length !== exports.PROOF_LENGTH) return false;
    return schnorr.verify(aggregatePubkey, this.getHashForSign(), this.proof);
  }
  __byteLength(headersOnly, includeProof) {
    const headerLength =
      4 + // features
      32 + // prevHash
      32 + // merkleRoot
      32 + // imMerkleRoot
      4 + // timestamp
      xfieldLength(this.xfield) +
      (includeProof
        ? varuint.encodingLength(this.proof.length) + this.proof.length
        : 0);
    if (headersOnly || !this.transactions) return headerLength;
    return (
      headerLength +
      varuint.encodingLength(this.transactions.length) +
      this.transactions.reduce((a, x) => a + x.byteLength(), 0)
    );
  }
  __toBuffer(headersOnly, includeProof = true) {
    const buffer = Buffer.alloc(this.__byteLength(headersOnly, includeProof));
    const bufferWriter = new bufferutils_1.BufferWriter(buffer);
    bufferWriter.writeInt32(this.features);
    bufferWriter.writeSlice(this.prevHash);
    bufferWriter.writeSlice(this.merkleRoot);
    bufferWriter.writeSlice(this.imMerkleRoot);
    bufferWriter.writeUInt32(this.timestamp);
    writeXField(bufferWriter, this.xfield);
    if (includeProof) bufferWriter.writeVarSlice(this.proof);
    if (headersOnly || !this.transactions) return buffer;
    bufferWriter.writeVarInt(this.transactions.length);
    this.transactions.forEach(tx => {
      const txSize = tx.byteLength();
      tx.toBuffer(buffer, bufferWriter.offset);
      bufferWriter.offset += txSize;
    });
    return buffer;
  }
}
exports.Block = Block;
