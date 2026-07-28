'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.UPDATABLE_OUTPUT_KEYS = exports.UPDATABLE_INPUT_KEYS = exports.UPDATABLE_GLOBAL_KEYS = void 0;
/**
 * The keys of `PsttGlobalUpdate`, enforced at run time by `Pstt.updateGlobal`.
 */
exports.UPDATABLE_GLOBAL_KEYS = [
  'xpub',
  'features',
  'fallbackLocktime',
  'txModifiable',
  'version',
  'unknownKeyVals',
];
/**
 * The keys of `PsttInputUpdate`, enforced at run time by `Pstt.updateInput`.
 */
exports.UPDATABLE_INPUT_KEYS = [
  'utxo',
  'sighashType',
  'redeemScript',
  'bip32Derivation',
  'ripemd160Preimages',
  'sha256Preimages',
  'hash160Preimages',
  'hash256Preimages',
  'sequence',
  'requiredTimeLocktime',
  'requiredHeightLocktime',
  'unknownKeyVals',
];
exports.UPDATABLE_OUTPUT_KEYS = [
  'redeemScript',
  'bip32Derivation',
  'unknownKeyVals',
];
