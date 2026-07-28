'use strict';
// Field type values defined by TIP-0174 (Partially Signed Tapyrus Transaction).
//
// Where a key type has the same meaning in BIP-174/BIP-370, TIP-0174 assigns it
// the same type value, so these constants line up with the PSBT ones except for
// the fields that Tapyrus does not have.
Object.defineProperty(exports, '__esModule', { value: true });
exports.PUBKEY_LENGTHS = exports.LOCKTIME_THRESHOLD = exports.EMPTY_KEYDATA_OUTPUT_TYPES = exports.EMPTY_KEYDATA_INPUT_TYPES = exports.EMPTY_KEYDATA_GLOBAL_TYPES = exports.RESERVED_OUTPUT_TYPES = exports.RESERVED_INPUT_TYPES = exports.RESERVED_GLOBAL_TYPES = exports.TxModifiable = exports.OutputTypes = exports.InputTypes = exports.GlobalTypes = exports.PSTT_VERSION = exports.MAGIC = void 0;
exports.isValidPubkeyLength = isValidPubkeyLength;
exports.isValidSighashType = isValidSighashType;
const transaction_1 = require('../transaction');
exports.MAGIC = Buffer.from('70737474ff', 'hex'); // "pstt" 0xFF
exports.PSTT_VERSION = 0;
var GlobalTypes;
(function(GlobalTypes) {
  GlobalTypes[(GlobalTypes['XPUB'] = 1)] = 'XPUB';
  GlobalTypes[(GlobalTypes['TX_FEATURES'] = 2)] = 'TX_FEATURES';
  GlobalTypes[(GlobalTypes['FALLBACK_LOCKTIME'] = 3)] = 'FALLBACK_LOCKTIME';
  GlobalTypes[(GlobalTypes['INPUT_COUNT'] = 4)] = 'INPUT_COUNT';
  GlobalTypes[(GlobalTypes['OUTPUT_COUNT'] = 5)] = 'OUTPUT_COUNT';
  GlobalTypes[(GlobalTypes['TX_MODIFIABLE'] = 6)] = 'TX_MODIFIABLE';
  GlobalTypes[(GlobalTypes['VERSION'] = 251)] = 'VERSION';
  GlobalTypes[(GlobalTypes['PROPRIETARY'] = 252)] = 'PROPRIETARY';
})(GlobalTypes || (exports.GlobalTypes = GlobalTypes = {}));
var InputTypes;
(function(InputTypes) {
  InputTypes[(InputTypes['UTXO'] = 0)] = 'UTXO';
  InputTypes[(InputTypes['PARTIAL_SIG'] = 2)] = 'PARTIAL_SIG';
  InputTypes[(InputTypes['SIGHASH_TYPE'] = 3)] = 'SIGHASH_TYPE';
  InputTypes[(InputTypes['REDEEM_SCRIPT'] = 4)] = 'REDEEM_SCRIPT';
  InputTypes[(InputTypes['BIP32_DERIVATION'] = 6)] = 'BIP32_DERIVATION';
  InputTypes[(InputTypes['FINAL_SCRIPTSIG'] = 7)] = 'FINAL_SCRIPTSIG';
  InputTypes[(InputTypes['RIPEMD160'] = 10)] = 'RIPEMD160';
  InputTypes[(InputTypes['SHA256'] = 11)] = 'SHA256';
  InputTypes[(InputTypes['HASH160'] = 12)] = 'HASH160';
  InputTypes[(InputTypes['HASH256'] = 13)] = 'HASH256';
  InputTypes[(InputTypes['PREVIOUS_TXID'] = 14)] = 'PREVIOUS_TXID';
  InputTypes[(InputTypes['OUTPUT_INDEX'] = 15)] = 'OUTPUT_INDEX';
  InputTypes[(InputTypes['SEQUENCE'] = 16)] = 'SEQUENCE';
  InputTypes[(InputTypes['REQUIRED_TIME_LOCKTIME'] = 17)] =
    'REQUIRED_TIME_LOCKTIME';
  InputTypes[(InputTypes['REQUIRED_HEIGHT_LOCKTIME'] = 18)] =
    'REQUIRED_HEIGHT_LOCKTIME';
  InputTypes[(InputTypes['PROPRIETARY'] = 252)] = 'PROPRIETARY';
})(InputTypes || (exports.InputTypes = InputTypes = {}));
var OutputTypes;
(function(OutputTypes) {
  OutputTypes[(OutputTypes['REDEEM_SCRIPT'] = 0)] = 'REDEEM_SCRIPT';
  OutputTypes[(OutputTypes['BIP32_DERIVATION'] = 2)] = 'BIP32_DERIVATION';
  OutputTypes[(OutputTypes['AMOUNT'] = 3)] = 'AMOUNT';
  OutputTypes[(OutputTypes['SCRIPT'] = 4)] = 'SCRIPT';
  OutputTypes[(OutputTypes['PROPRIETARY'] = 252)] = 'PROPRIETARY';
})(OutputTypes || (exports.OutputTypes = OutputTypes = {}));
/**
 * Bitfield of PSTT_GLOBAL_TX_MODIFIABLE.
 */
var TxModifiable;
(function(TxModifiable) {
  TxModifiable[(TxModifiable['INPUTS'] = 1)] = 'INPUTS';
  TxModifiable[(TxModifiable['OUTPUTS'] = 2)] = 'OUTPUTS';
  TxModifiable[(TxModifiable['HAS_SIGHASH_SINGLE'] = 4)] = 'HAS_SIGHASH_SINGLE';
})(TxModifiable || (exports.TxModifiable = TxModifiable = {}));
/**
 * The global unsigned transaction of BIP-174. TIP-0174 has no counterpart, so
 * the type value is reserved and a PSTT carrying it must be rejected.
 */
exports.RESERVED_GLOBAL_TYPES = [0x00];
/**
 * Segregated Witness, proof-of-reserves and Taproot fields of BIP-174 and its
 * successors. Tapyrus has neither Segregated Witness nor Taproot, so these type
 * values are reserved and must not be used.
 *
 * 0x01 witness UTXO, 0x05 witness script, 0x08 finalized scriptWitness,
 * 0x09 proof-of-reserves commitment, 0x13-0x18 the Taproot fields of BIP-371.
 */
exports.RESERVED_INPUT_TYPES = [
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
exports.RESERVED_OUTPUT_TYPES = [0x01, 0x05, 0x06, 0x07];
/**
 * Type values whose definition lists no key data. A record of one of these
 * types with a non-empty `<keydata>` is invalid.
 */
exports.EMPTY_KEYDATA_GLOBAL_TYPES = [
  GlobalTypes.TX_FEATURES,
  GlobalTypes.FALLBACK_LOCKTIME,
  GlobalTypes.INPUT_COUNT,
  GlobalTypes.OUTPUT_COUNT,
  GlobalTypes.TX_MODIFIABLE,
  GlobalTypes.VERSION,
];
exports.EMPTY_KEYDATA_INPUT_TYPES = [
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
exports.EMPTY_KEYDATA_OUTPUT_TYPES = [
  OutputTypes.REDEEM_SCRIPT,
  OutputTypes.AMOUNT,
  OutputTypes.SCRIPT,
];
/**
 * The boundary between height-based and time-based locktimes.
 */
exports.LOCKTIME_THRESHOLD = 500000000;
/**
 * The lengths a public key used as `<keydata>` may have: compressed or
 * uncompressed.
 */
exports.PUBKEY_LENGTHS = [33, 65];
function isValidPubkeyLength(pubkey) {
  return exports.PUBKEY_LENGTHS.indexOf(pubkey.length) !== -1;
}
/**
 * The sighash types TIP-0174 defines: SIGHASH_ALL, SIGHASH_NONE and
 * SIGHASH_SINGLE, each optionally combined with SIGHASH_ANYONECANPAY.
 */
function isValidSighashType(sighashType) {
  const base = sighashType & ~transaction_1.Transaction.SIGHASH_ANYONECANPAY;
  return (
    base >= transaction_1.Transaction.SIGHASH_ALL &&
    base <= transaction_1.Transaction.SIGHASH_SINGLE
  );
}
