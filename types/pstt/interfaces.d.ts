import { PsttRecord } from './container';
/**
 * A BIP 32 derivation path attached to a public key.
 */
export interface Bip32Derivation {
    masterFingerprint: Buffer;
    pubkey: Buffer;
    path: string;
}
/**
 * PSTT_GLOBAL_XPUB: an extended public key with the path it was derived at.
 */
export interface GlobalXpub {
    extendedPubkey: Buffer;
    masterFingerprint: Buffer;
    path: string;
}
/**
 * PSTT_IN_PARTIAL_SIG: a signature keyed by the public key that produced it.
 * The signature is a DER-encoded ECDSA signature or a 64-byte Schnorr
 * signature, each followed by the 1-byte sighash type.
 */
export interface PartialSig {
    pubkey: Buffer;
    signature: Buffer;
}
/**
 * Hash preimages, keyed by the hex of the hash they produce.
 */
export interface PreimageMap {
    [hash: string]: Buffer;
}
/**
 * The complete keys of the records a map was parsed from, in the order they
 * appeared in. TIP-0174 prescribes no order, so the only way to serialize a
 * parsed PSTT back to the bytes it came from is to remember the order it used.
 * Absent on a PSTT this process is building, which has no order to preserve.
 */
export type RecordOrder = string[];
export interface PsttGlobal {
    xpub: GlobalXpub[];
    features: number;
    fallbackLocktime?: number;
    txModifiable?: number;
    version?: number;
    unknownKeyVals: PsttRecord[];
    recordOrder?: RecordOrder;
}
export interface PsttInput {
    /** The complete previous transaction, in Tapyrus network serialization. */
    utxo?: Buffer;
    partialSig: PartialSig[];
    sighashType?: number;
    redeemScript?: Buffer;
    bip32Derivation: Bip32Derivation[];
    finalScriptSig?: Buffer;
    ripemd160Preimages: PreimageMap;
    sha256Preimages: PreimageMap;
    hash160Preimages: PreimageMap;
    hash256Preimages: PreimageMap;
    /** The malleability-fixed txid, in transaction serialization order. */
    previousTxid: Buffer;
    outputIndex: number;
    sequence?: number;
    requiredTimeLocktime?: number;
    requiredHeightLocktime?: number;
    unknownKeyVals: PsttRecord[];
    recordOrder?: RecordOrder;
}
export interface PsttOutput {
    redeemScript?: Buffer;
    bip32Derivation: Bip32Derivation[];
    amount: number;
    script: Buffer;
    unknownKeyVals: PsttRecord[];
    recordOrder?: RecordOrder;
}
export interface PsttGlobalUpdate {
    xpub?: GlobalXpub[];
    features?: number;
    fallbackLocktime?: number;
    txModifiable?: number;
    version?: number;
    unknownKeyVals?: PsttRecord[];
}
/**
 * The keys of `PsttGlobalUpdate`, enforced at run time by `Pstt.updateGlobal`.
 */
export declare const UPDATABLE_GLOBAL_KEYS: string[];
/**
 * The input fields an Updater owns.
 *
 * `partialSig` and `finalScriptSig` are deliberately absent: they belong to the
 * Signer and to the Input Finalizer, and TIP-0174 forbids an Updater to alter
 * them. `Pstt` rejects any other key at run time as well, so a JavaScript
 * caller cannot reach them either.
 */
export interface PsttInputUpdate {
    utxo?: Buffer;
    sighashType?: number;
    redeemScript?: Buffer;
    bip32Derivation?: Bip32Derivation[];
    ripemd160Preimages?: PreimageMap;
    sha256Preimages?: PreimageMap;
    hash160Preimages?: PreimageMap;
    hash256Preimages?: PreimageMap;
    sequence?: number;
    requiredTimeLocktime?: number;
    requiredHeightLocktime?: number;
    unknownKeyVals?: PsttRecord[];
}
/**
 * The keys of `PsttInputUpdate`, enforced at run time by `Pstt.updateInput`.
 */
export declare const UPDATABLE_INPUT_KEYS: string[];
/**
 * The output fields an Updater owns. `amount` and `script` are absent because
 * changing them would alter the output, which is the Constructor's business.
 */
export interface PsttOutputUpdate {
    redeemScript?: Buffer;
    bip32Derivation?: Bip32Derivation[];
    unknownKeyVals?: PsttRecord[];
}
export declare const UPDATABLE_OUTPUT_KEYS: string[];
/**
 * The outpoint a new input spends. `previousTxid` accepts either the 32 bytes
 * in transaction serialization order, or the txid as displayed (hex, reversed).
 */
export interface PsttInputAdd extends PsttInputUpdate {
    previousTxid: Buffer | string;
    outputIndex: number;
}
export interface PsttOutputAdd extends PsttOutputUpdate {
    amount: number;
    script?: Buffer;
    address?: string;
}
