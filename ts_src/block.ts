import { BufferReader, BufferWriter, reverseBuffer } from './bufferutils';
import * as bcrypto from './crypto';
import * as schnorr from './schnorr';
import { Transaction } from './transaction';
import * as types from './types';

const fastMerkleRoot = require('merkle-lib/fastRoot');
const typeforce = require('typeforce');
const varuint = require('varuint-bitcoin');

const errorMerkleNoTxes = new TypeError(
  'Cannot compute merkle root for zero transactions',
);

/** The only value nFeatures may take. */
export const BLOCK_FEATURES = 1;

/** The length of the Schnorr signature a signed block carries. */
export const PROOF_LENGTH = 64;

/**
 * The extension field of a block header. Its payload depends on the type, and
 * the two defined payloads are not encoded the same way: an aggregate public
 * key is a length-prefixed vector, while a maximum block size is four raw
 * bytes.
 */
export enum XFieldType {
  NONE = 0,
  AGGREGATE_PUBKEY = 1,
  MAX_BLOCK_SIZE = 2,
}

export interface XField {
  type: XFieldType;
  /** The aggregate public key, for XFieldType.AGGREGATE_PUBKEY. */
  aggregatePubkey?: Buffer;
  /** The maximum block size, for XFieldType.MAX_BLOCK_SIZE. */
  maxBlockSize?: number;
}

const AGGREGATE_PUBKEY_LENGTH = 33;

/**
 * features, prevHash, merkleRoot, imMerkleRoot and timestamp, plus an empty
 * xfield and an empty proof.
 */
const MIN_HEADER_LENGTH = 4 + 32 + 32 + 32 + 4 + 1 + 1;

function readXField(bufferReader: BufferReader): XField {
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

function writeXField(bufferWriter: BufferWriter, xfield: XField): void {
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

function xfieldLength(xfield: XField): number {
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

export class Block {
  static fromBuffer(buffer: Buffer): Block {
    if (buffer.length < MIN_HEADER_LENGTH)
      throw new Error(`Buffer too small (< ${MIN_HEADER_LENGTH} bytes)`);

    const bufferReader = new BufferReader(buffer);

    const block = new Block();
    block.features = bufferReader.readInt32();
    block.prevHash = bufferReader.readSlice(32);
    block.merkleRoot = bufferReader.readSlice(32);
    block.imMerkleRoot = bufferReader.readSlice(32);
    block.timestamp = bufferReader.readUInt32();
    block.xfield = readXField(bufferReader);
    block.proof = bufferReader.readVarSlice();

    if (bufferReader.offset === buffer.length) return block;

    const readTransaction = (): Transaction => {
      const tx = Transaction.fromBuffer(
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

  static fromHex(hex: string): Block {
    return Block.fromBuffer(Buffer.from(hex, 'hex'));
  }

  /**
   * The merkle root over the transaction hashes, which include the scriptSig
   * of every input. This is the `merkleRoot` of the header.
   */
  static calculateMerkleRoot(transactions: Transaction[]): Buffer {
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
  static calculateImMerkleRoot(transactions: Transaction[]): Buffer {
    typeforce([{ getMalFixHash: types.Function }], transactions);
    if (transactions.length === 0) throw errorMerkleNoTxes;

    const hashes = transactions.map(transaction => transaction.getMalFixHash());

    return fastMerkleRoot(hashes, bcrypto.hash256);
  }

  features: number = BLOCK_FEATURES;
  prevHash?: Buffer = undefined;
  merkleRoot?: Buffer = undefined;
  imMerkleRoot?: Buffer = undefined;
  timestamp: number = 0;
  xfield: XField = { type: XFieldType.NONE };
  proof: Buffer = Buffer.alloc(0);
  transactions?: Transaction[] = undefined;

  byteLength(headersOnly?: boolean): number {
    return this.__byteLength(headersOnly, true);
  }

  /** The block identifier, over the whole header including the proof. */
  getHash(): Buffer {
    return bcrypto.hash256(this.toBuffer(true));
  }

  getId(): string {
    return reverseBuffer(this.getHash()).toString('hex');
  }

  /** What the signer signs: the header without the proof. */
  getHashForSign(): Buffer {
    return bcrypto.hash256(this.__toBuffer(true, false));
  }

  getUTCDate(): Date {
    const date = new Date(0); // epoch
    date.setUTCSeconds(this.timestamp);

    return date;
  }

  toBuffer(headersOnly?: boolean): Buffer {
    return this.__toBuffer(headersOnly, true);
  }

  toHex(headersOnly?: boolean): string {
    return this.toBuffer(headersOnly).toString('hex');
  }

  /** Both merkle roots of the header must match the transactions. */
  checkMerkleRoot(): boolean {
    if (!this.transactions) throw errorMerkleNoTxes;

    return (
      this.merkleRoot!.equals(Block.calculateMerkleRoot(this.transactions)) &&
      this.imMerkleRoot!.equals(Block.calculateImMerkleRoot(this.transactions))
    );
  }

  /**
   * Verify the block signature against the aggregate public key that was in
   * force at this height. The key is not stored in the library: it starts in
   * the genesis block and is replaced by later blocks through the xfield, so
   * the caller has to supply the one that applies.
   */
  checkProof(aggregatePubkey: Buffer): boolean {
    typeforce(types.Buffer, aggregatePubkey);

    if (this.features !== BLOCK_FEATURES) return false;
    if (this.proof.length !== PROOF_LENGTH) return false;

    return schnorr.verify(aggregatePubkey, this.getHashForSign(), this.proof);
  }

  private __byteLength(
    headersOnly: boolean | undefined,
    includeProof: boolean,
  ): number {
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

  private __toBuffer(
    headersOnly?: boolean,
    includeProof: boolean = true,
  ): Buffer {
    const buffer: Buffer = Buffer.alloc(
      this.__byteLength(headersOnly, includeProof),
    );

    const bufferWriter = new BufferWriter(buffer);

    bufferWriter.writeInt32(this.features);
    bufferWriter.writeSlice(this.prevHash!);
    bufferWriter.writeSlice(this.merkleRoot!);
    bufferWriter.writeSlice(this.imMerkleRoot!);
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
