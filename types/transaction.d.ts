export interface Output {
    script: Buffer;
    value: number;
}
export interface Input {
    hash: Buffer;
    index: number;
    script: Buffer;
    sequence: number;
}
export declare class Transaction {
    static readonly DEFAULT_SEQUENCE = 4294967295;
    static readonly SIGHASH_ALL = 1;
    static readonly SIGHASH_NONE = 2;
    static readonly SIGHASH_SINGLE = 3;
    static readonly SIGHASH_ANYONECANPAY = 128;
    static fromBuffer(buffer: Buffer, _NO_STRICT?: boolean): Transaction;
    static fromHex(hex: string): Transaction;
    static isCoinbaseHash(buffer: Buffer): boolean;
    version: number;
    locktime: number;
    ins: Input[];
    outs: Output[];
    isCoinbase(): boolean;
    addInput(hash: Buffer, index: number, sequence?: number, scriptSig?: Buffer): number;
    addOutput(scriptPubKey: Buffer, value: number): number;
    /**
     * The size of the serialized transaction in bytes, scriptSig included.
     */
    byteLength(): number;
    /**
     * The size in bytes of the serialization the hashMalFix txid is taken from.
     * The scriptSig of each input is left out.
     */
    byteLengthMalFix(): number;
    clone(): Transaction;
    /**
     * Hash transaction for signing a specific input.
     *
     * Bitcoin uses a different hash for each signed transaction input.
     * This method copies the transaction, makes the necessary changes based on the
     * hashType, and then hashes the result.
     * This hash can then be used to sign the provided transaction input.
     */
    hashForSignature(inIndex: number, prevOutScript: Buffer, hashType: number): Buffer;
    getHash(): Buffer;
    getId(): string;
    toBuffer(buffer?: Buffer, initialOffset?: number): Buffer;
    toHex(): string;
    setInputScript(index: number, scriptSig: Buffer): void;
    /**
     * @param mulFix serialize without the scriptSig of each input, as the
     *   hashMalFix txid does.
     */
    private __byteLength;
    private __toBuffer;
}
