export declare const MAGIC: Buffer;
export declare const PSTT_VERSION = 0;
export declare enum GlobalTypes {
    XPUB = 1,
    TX_FEATURES = 2,
    FALLBACK_LOCKTIME = 3,
    INPUT_COUNT = 4,
    OUTPUT_COUNT = 5,
    TX_MODIFIABLE = 6,
    VERSION = 251,
    PROPRIETARY = 252
}
export declare enum InputTypes {
    UTXO = 0,
    PARTIAL_SIG = 2,
    SIGHASH_TYPE = 3,
    REDEEM_SCRIPT = 4,
    BIP32_DERIVATION = 6,
    FINAL_SCRIPTSIG = 7,
    RIPEMD160 = 10,
    SHA256 = 11,
    HASH160 = 12,
    HASH256 = 13,
    PREVIOUS_TXID = 14,
    OUTPUT_INDEX = 15,
    SEQUENCE = 16,
    REQUIRED_TIME_LOCKTIME = 17,
    REQUIRED_HEIGHT_LOCKTIME = 18,
    PROPRIETARY = 252
}
export declare enum OutputTypes {
    REDEEM_SCRIPT = 0,
    BIP32_DERIVATION = 2,
    AMOUNT = 3,
    SCRIPT = 4,
    PROPRIETARY = 252
}
/**
 * Bitfield of PSTT_GLOBAL_TX_MODIFIABLE.
 */
export declare enum TxModifiable {
    INPUTS = 1,
    OUTPUTS = 2,
    HAS_SIGHASH_SINGLE = 4
}
/**
 * The global unsigned transaction of BIP-174. TIP-0174 has no counterpart, so
 * the type value is reserved and a PSTT carrying it must be rejected.
 */
export declare const RESERVED_GLOBAL_TYPES: number[];
/**
 * Segregated Witness, proof-of-reserves and Taproot fields of BIP-174 and its
 * successors. Tapyrus has neither Segregated Witness nor Taproot, so these type
 * values are reserved and must not be used.
 *
 * 0x01 witness UTXO, 0x05 witness script, 0x08 finalized scriptWitness,
 * 0x09 proof-of-reserves commitment, 0x13-0x18 the Taproot fields of BIP-371.
 */
export declare const RESERVED_INPUT_TYPES: number[];
/**
 * The witness script (0x01) and the Taproot fields (0x05-0x07) of the output
 * map, reserved for the same reason.
 */
export declare const RESERVED_OUTPUT_TYPES: number[];
/**
 * Type values whose definition lists no key data. A record of one of these
 * types with a non-empty `<keydata>` is invalid.
 */
export declare const EMPTY_KEYDATA_GLOBAL_TYPES: number[];
export declare const EMPTY_KEYDATA_INPUT_TYPES: number[];
export declare const EMPTY_KEYDATA_OUTPUT_TYPES: number[];
/**
 * The boundary between height-based and time-based locktimes.
 */
export declare const LOCKTIME_THRESHOLD = 500000000;
/**
 * The lengths a public key used as `<keydata>` may have: compressed or
 * uncompressed.
 */
export declare const PUBKEY_LENGTHS: number[];
export declare function isValidPubkeyLength(pubkey: Buffer): boolean;
/**
 * The sighash types TIP-0174 defines: SIGHASH_ALL, SIGHASH_NONE and
 * SIGHASH_SINGLE, each optionally combined with SIGHASH_ANYONECANPAY.
 */
export declare function isValidSighashType(sighashType: number): boolean;
