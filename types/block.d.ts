import { Transaction } from './transaction';
/** The only value nFeatures may take. */
export declare const BLOCK_FEATURES = 1;
/** The length of the Schnorr signature a signed block carries. */
export declare const PROOF_LENGTH = 64;
/**
 * The extension field of a block header. Its payload depends on the type, and
 * the two defined payloads are not encoded the same way: an aggregate public
 * key is a length-prefixed vector, while a maximum block size is four raw
 * bytes.
 */
export declare enum XFieldType {
    NONE = 0,
    AGGREGATE_PUBKEY = 1,
    MAX_BLOCK_SIZE = 2
}
export interface XField {
    type: XFieldType;
    /** The aggregate public key, for XFieldType.AGGREGATE_PUBKEY. */
    aggregatePubkey?: Buffer;
    /** The maximum block size, for XFieldType.MAX_BLOCK_SIZE. */
    maxBlockSize?: number;
}
export declare class Block {
    static fromBuffer(buffer: Buffer): Block;
    static fromHex(hex: string): Block;
    /**
     * The merkle root over the transaction hashes, which include the scriptSig
     * of every input. This is the `merkleRoot` of the header.
     */
    static calculateMerkleRoot(transactions: Transaction[]): Buffer;
    /**
     * The merkle root over the hashMalFix of the transactions, which omit the
     * scriptSig. This is the `imMerkleRoot` of the header, and it does not
     * change when a scriptSig is altered.
     */
    static calculateImMerkleRoot(transactions: Transaction[]): Buffer;
    features: number;
    prevHash?: Buffer;
    merkleRoot?: Buffer;
    imMerkleRoot?: Buffer;
    timestamp: number;
    xfield: XField;
    proof: Buffer;
    transactions?: Transaction[];
    byteLength(headersOnly?: boolean): number;
    /** The block identifier, over the whole header including the proof. */
    getHash(): Buffer;
    getId(): string;
    /** What the signer signs: the header without the proof. */
    getHashForSign(): Buffer;
    getUTCDate(): Date;
    toBuffer(headersOnly?: boolean): Buffer;
    toHex(headersOnly?: boolean): string;
    /** Both merkle roots of the header must match the transactions. */
    checkMerkleRoot(): boolean;
    /**
     * Verify the block signature against the aggregate public key that was in
     * force at this height. The key is not stored in the library: it starts in
     * the genesis block and is replaced by later blocks through the xfield, so
     * the caller has to supply the one that applies.
     */
    checkProof(aggregatePubkey: Buffer): boolean;
    private __byteLength;
    private __toBuffer;
}
