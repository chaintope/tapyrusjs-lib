// Field type values defined by TIP-0174 (Partially Signed Tapyrus Transaction).
//
// Where a key type has the same meaning in BIP-174/BIP-370, TIP-0174 assigns it
// the same type value, so these constants line up with the PSBT ones except for
// the fields that Tapyrus does not have.

import { Transaction } from '../transaction';

export const MAGIC: Buffer = Buffer.from('70737474ff', 'hex'); // "pstt" 0xFF

export const PSTT_VERSION = 0;

export enum GlobalTypes {
  XPUB = 0x01,
  TX_FEATURES = 0x02,
  FALLBACK_LOCKTIME = 0x03,
  INPUT_COUNT = 0x04,
  OUTPUT_COUNT = 0x05,
  TX_MODIFIABLE = 0x06,
  VERSION = 0xfb,
  PROPRIETARY = 0xfc,
}

export enum InputTypes {
  UTXO = 0x00,
  PARTIAL_SIG = 0x02,
  SIGHASH_TYPE = 0x03,
  REDEEM_SCRIPT = 0x04,
  BIP32_DERIVATION = 0x06,
  FINAL_SCRIPTSIG = 0x07,
  RIPEMD160 = 0x0a,
  SHA256 = 0x0b,
  HASH160 = 0x0c,
  HASH256 = 0x0d,
  PREVIOUS_TXID = 0x0e,
  OUTPUT_INDEX = 0x0f,
  SEQUENCE = 0x10,
  REQUIRED_TIME_LOCKTIME = 0x11,
  REQUIRED_HEIGHT_LOCKTIME = 0x12,
  PROPRIETARY = 0xfc,
}

export enum OutputTypes {
  REDEEM_SCRIPT = 0x00,
  BIP32_DERIVATION = 0x02,
  AMOUNT = 0x03,
  SCRIPT = 0x04,
  PROPRIETARY = 0xfc,
}

/**
 * Bitfield of PSTT_GLOBAL_TX_MODIFIABLE.
 */
export enum TxModifiable {
  INPUTS = 0x01,
  OUTPUTS = 0x02,
  HAS_SIGHASH_SINGLE = 0x04,
}

/**
 * The global unsigned transaction of BIP-174. TIP-0174 has no counterpart, so
 * the type value is reserved and a PSTT carrying it must be rejected.
 */
export const RESERVED_GLOBAL_TYPES: number[] = [0x00];

/**
 * Segregated Witness, proof-of-reserves and Taproot fields of BIP-174 and its
 * successors. Tapyrus has neither Segregated Witness nor Taproot, so these type
 * values are reserved and must not be used.
 *
 * 0x01 witness UTXO, 0x05 witness script, 0x08 finalized scriptWitness,
 * 0x09 proof-of-reserves commitment, 0x13-0x18 the Taproot fields of BIP-371.
 */
export const RESERVED_INPUT_TYPES: number[] = [
  0x01,
  0x05,
  0x08,
  0x09,
  0x13,
  0x14,
  0x15,
  0x16,
  0x17,
  0x18,
];

/**
 * The witness script (0x01) and the Taproot fields (0x05-0x07) of the output
 * map, reserved for the same reason.
 */
export const RESERVED_OUTPUT_TYPES: number[] = [0x01, 0x05, 0x06, 0x07];

/**
 * Type values whose definition lists no key data. A record of one of these
 * types with a non-empty `<keydata>` is invalid.
 */
export const EMPTY_KEYDATA_GLOBAL_TYPES: number[] = [
  GlobalTypes.TX_FEATURES,
  GlobalTypes.FALLBACK_LOCKTIME,
  GlobalTypes.INPUT_COUNT,
  GlobalTypes.OUTPUT_COUNT,
  GlobalTypes.TX_MODIFIABLE,
  GlobalTypes.VERSION,
];

export const EMPTY_KEYDATA_INPUT_TYPES: number[] = [
  InputTypes.UTXO,
  InputTypes.SIGHASH_TYPE,
  InputTypes.REDEEM_SCRIPT,
  InputTypes.FINAL_SCRIPTSIG,
  InputTypes.PREVIOUS_TXID,
  InputTypes.OUTPUT_INDEX,
  InputTypes.SEQUENCE,
  InputTypes.REQUIRED_TIME_LOCKTIME,
  InputTypes.REQUIRED_HEIGHT_LOCKTIME,
];

export const EMPTY_KEYDATA_OUTPUT_TYPES: number[] = [
  OutputTypes.REDEEM_SCRIPT,
  OutputTypes.AMOUNT,
  OutputTypes.SCRIPT,
];

/**
 * The boundary between height-based and time-based locktimes.
 */
export const LOCKTIME_THRESHOLD = 500000000;

/**
 * The lengths a public key used as `<keydata>` may have: compressed or
 * uncompressed.
 */
export const PUBKEY_LENGTHS: number[] = [33, 65];

export function isValidPubkeyLength(pubkey: Buffer): boolean {
  return PUBKEY_LENGTHS.indexOf(pubkey.length) !== -1;
}

/**
 * The sighash types TIP-0174 defines: SIGHASH_ALL, SIGHASH_NONE and
 * SIGHASH_SINGLE, each optionally combined with SIGHASH_ANYONECANPAY.
 */
export function isValidSighashType(sighashType: number): boolean {
  const base = sighashType & ~Transaction.SIGHASH_ANYONECANPAY;
  return base >= Transaction.SIGHASH_ALL && base <= Transaction.SIGHASH_SINGLE;
}
