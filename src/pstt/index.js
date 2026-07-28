'use strict';
// Partially Signed Tapyrus Transaction (PSTT), as defined by TIP-0174.
//
// The data model is the constructable one of BIP-370: the transaction is held
// as per-input and per-output fields rather than as a fixed unsigned
// transaction, so inputs and outputs can be added after creation and after
// some signatures have been collected.
var __rest =
  (this && this.__rest) ||
  function(s, e) {
    var t = {};
    for (var p in s)
      if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === 'function')
      for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
        if (
          e.indexOf(p[i]) < 0 &&
          Object.prototype.propertyIsEnumerable.call(s, p[i])
        )
          t[p[i]] = s[p[i]];
      }
    return t;
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.Pstt = exports.resolveLocktime = exports.unregisterScriptSigBuilder = exports.registerScriptSigBuilder = exports.MAGIC = exports.TxModifiable = void 0;
exports.signatureScheme = signatureScheme;
const address_1 = require('../address');
const classify = require('../classify');
const crypto_1 = require('../crypto');
const ecpair_1 = require('../ecpair');
const networks_1 = require('../networks');
const schnorr = require('../schnorr');
const bscript = require('../script');
const transaction_1 = require('../transaction');
const container_1 = require('./container');
const converter_1 = require('./converter');
const fields_1 = require('./fields');
Object.defineProperty(exports, 'MAGIC', {
  enumerable: true,
  get: function() {
    return fields_1.MAGIC;
  },
});
Object.defineProperty(exports, 'TxModifiable', {
  enumerable: true,
  get: function() {
    return fields_1.TxModifiable;
  },
});
const finalizer_1 = require('./finalizer');
const interfaces_1 = require('./interfaces');
const locktime_1 = require('./locktime');
Object.defineProperty(exports, 'resolveLocktime', {
  enumerable: true,
  get: function() {
    return locktime_1.resolveLocktime;
  },
});
var finalizer_2 = require('./finalizer');
Object.defineProperty(exports, 'registerScriptSigBuilder', {
  enumerable: true,
  get: function() {
    return finalizer_2.registerScriptSigBuilder;
  },
});
Object.defineProperty(exports, 'unregisterScriptSigBuilder', {
  enumerable: true,
  get: function() {
    return finalizer_2.unregisterScriptSigBuilder;
  },
});
const SCHNORR_RAW_SIGNATURE_LENGTH = 64; // Rx(32) || s(32)
const SCHNORR_SIGNATURE_LENGTH = SCHNORR_RAW_SIGNATURE_LENGTH + 1; // + sighash type
const DEFAULT_FEATURES = 1;
/**
 * The scheme of a partial signature value, decided by its length exactly as
 * the Tapyrus script interpreter decides it.
 */
function signatureScheme(signature) {
  return signature.length === SCHNORR_SIGNATURE_LENGTH ? 'schnorr' : 'ecdsa';
}
function sighashTypeOf(signature) {
  return signature[signature.length - 1];
}
/**
 * The sequence number an input contributes to the transaction: PSTT_IN_SEQUENCE
 * if present, the default otherwise, since an absent record means the default.
 */
function sequenceOf(input) {
  return input.sequence === undefined
    ? transaction_1.Transaction.DEFAULT_SEQUENCE
    : input.sequence;
}
function isP2SHType(scriptType) {
  return (
    scriptType === classify.types.P2SH || scriptType === classify.types.CP2SH
  );
}
/**
 * The HASH160 committed in a P2SH or CP2SH scriptPubKey. For CP2SH the hash
 * follows the `<color identifier> OP_COLOR` prefix.
 */
function scriptHashOf(script, scriptType) {
  const chunks = bscript.decompile(script);
  if (!chunks) throw new Error('Invalid scriptPubKey');
  return chunks[scriptType === classify.types.CP2SH ? 3 : 1];
}
/**
 * The public key hash of a P2PKH or CP2PKH scriptPubKey.
 */
function pubkeyHashOf(script, scriptType) {
  const chunks = bscript.decompile(script);
  if (!chunks) throw new Error('Invalid scriptPubKey');
  return chunks[scriptType === classify.types.CP2PKH ? 4 : 2];
}
function mergeRecords(mine, theirs) {
  const keys = new Set(mine.map(container_1.recordKey));
  return mine.concat(
    theirs.filter(record => !keys.has((0, container_1.recordKey)(record))),
  );
}
/**
 * PSTT_GLOBAL_TX_MODIFIABLE of a combined PSTT.
 *
 * Merging records by their complete key keeps one copy's value and discards
 * the other's, which would resurrect a flag that the other copy cleared when
 * it collected a signature — leaving a PSTT that carries a SIGHASH_ALL
 * signature and still claims to accept further inputs. A flag that permits a
 * modification therefore survives only while both copies permit it; every
 * other bit, Has SIGHASH_SINGLE included, is the union of the two.
 */
function combineModifiable(mine, theirs) {
  if (mine === undefined && theirs === undefined) return undefined;
  const permissive =
    fields_1.TxModifiable.INPUTS | fields_1.TxModifiable.OUTPUTS;
  const a = mine || 0;
  const b = theirs || 0;
  return (a & b & permissive) | ((a | b) & ~permissive);
}
/**
 * TIP-0174 reserves every bit of PSTT_GLOBAL_TX_MODIFIABLE above Has
 * SIGHASH_SINGLE and requires it to be 0, so a value carrying one describes a
 * modification rule this format does not define. Serializing it would also
 * truncate it, since the field is a single byte.
 */
function checkTxModifiableValue(value) {
  if (value !== undefined && !(0, fields_1.isValidTxModifiable)(value))
    throw new Error(
      'PSTT_GLOBAL_TX_MODIFIABLE must leave the bits TIP-0174 reserves at 0',
    );
}
/**
 * Whether a PSTT_IN_PARTIAL_SIG record verifies against the transaction, under
 * the scheme its length selects and the sighash type its last byte names.
 *
 * A record that is not a signature at all — malformed DER, a public key that is
 * not a point — is not valid, so the decoders are allowed to fail here rather
 * than to raise. Nothing about the sighash type is judged: the callers have
 * already decided which types they accept.
 */
function verifyPartialSig(tx, inputIndex, scriptCode, sig) {
  try {
    const hash = tx.hashForSignature(
      inputIndex,
      scriptCode,
      sighashTypeOf(sig.signature),
    );
    if (signatureScheme(sig.signature) === 'schnorr')
      return schnorr.verify(
        sig.pubkey,
        hash,
        sig.signature.subarray(0, SCHNORR_RAW_SIGNATURE_LENGTH),
      );
    const decoded = bscript.signature.decode(sig.signature);
    return (0, ecpair_1.fromPublicKey)(sig.pubkey).verify(
      hash,
      decoded.signature,
    );
  } catch (e) {
    return false;
  }
}
/**
 * Whether a script can be satisfied with a signature by this public key: the
 * key behind the hash of a P2PKH or CP2PKH script, or a key that appears in
 * the script itself, as in P2PK and multisig.
 */
function scriptInvolvesPubkey(script, pubkey) {
  const scriptType = classify.output(script);
  if (
    scriptType === classify.types.P2PKH ||
    scriptType === classify.types.CP2PKH
  )
    return (0, crypto_1.hash160)(pubkey).equals(
      pubkeyHashOf(script, scriptType),
    );
  const chunks = bscript.decompile(script);
  return (
    !!chunks &&
    chunks.some(chunk => Buffer.isBuffer(chunk) && chunk.equals(pubkey))
  );
}
/**
 * Copy the fields of an update onto a target, rejecting any key the role that
 * issues the update does not own. Without this an `Object.assign` would let an
 * Updater reach fields TIP-0174 reserves for the Signer and the Input
 * Finalizer, such as `partialSig` and `finalScriptSig`.
 */
function applyUpdate(target, update, updatable, what) {
  for (const key of Object.keys(update)) {
    if (updatable.indexOf(key) === -1)
      throw new Error(`An Updater must not set ${key} on ${what}`);
    const value = update[key];
    if (value !== undefined) target[key] = value;
  }
  return target;
}
/**
 * The locktime the inputs resolve to, or NaN when they contradict each other.
 * Used to compare a hypothetical set of inputs against the current one, where a
 * contradiction counts as a change rather than as an error of its own.
 */
function locktimeOrNaN(inputs, fallbackLocktime) {
  try {
    return (0, locktime_1.resolveLocktime)(inputs, fallbackLocktime);
  } catch (e) {
    return NaN;
  }
}
/**
 * Pstt fulfills every role of TIP-0174.
 *
 * Creator: `new Pstt()`, `setFeatures`, `setFallbackLocktime`,
 *   `setInputsModifiable`, `setOutputsModifiable`.
 * Constructor: `addInput`, `addOutput`, `addInputOutputPair`,
 *   `finishConstruction`.
 * Updater: `updateGlobal`, `updateInput`, `updateOutput`.
 * Signer: `signInput`, `signAllInputs`, `hashForSignature`,
 *   `validateSignaturesOfInput`.
 * Combiner: `combine`.
 * Input Finalizer: `finalizeInput`, `finalizeAllInputs`.
 * Transaction Extractor: `extractTransaction`.
 */
class Pstt {
  static fromBuffer(buffer, opts = {}) {
    return new Pstt(
      opts,
      (0, converter_1.fromRaw)((0, container_1.decode)(buffer)),
    );
  }
  static fromBase64(data, opts = {}) {
    return Pstt.fromBuffer(Buffer.from(data, 'base64'), opts);
  }
  static fromHex(data, opts = {}) {
    return Pstt.fromBuffer(Buffer.from(data, 'hex'), opts);
  }
  constructor(opts = {}, data = emptyData()) {
    this.data = data;
    this.opts = Object.assign({ network: networks_1.prod }, opts);
  }
  get global() {
    return this.data.global;
  }
  get inputs() {
    return this.data.inputs;
  }
  get outputs() {
    return this.data.outputs;
  }
  // --- Creator ---
  setFeatures(features) {
    return this.updateGlobal({ features });
  }
  setFallbackLocktime(locktime) {
    return this.updateGlobal({ fallbackLocktime: locktime });
  }
  setInputsModifiable(modifiable) {
    return this.setModifiableFlag(fields_1.TxModifiable.INPUTS, modifiable);
  }
  setOutputsModifiable(modifiable) {
    return this.setModifiableFlag(fields_1.TxModifiable.OUTPUTS, modifiable);
  }
  isInputsModifiable() {
    return this.hasModifiableFlag(fields_1.TxModifiable.INPUTS);
  }
  isOutputsModifiable() {
    return this.hasModifiableFlag(fields_1.TxModifiable.OUTPUTS);
  }
  hasSighashSingle() {
    return this.hasModifiableFlag(fields_1.TxModifiable.HAS_SIGHASH_SINGLE);
  }
  // --- Constructor ---
  /**
   * Declare construction finished by clearing the Inputs Modifiable and
   * Outputs Modifiable flags.
   */
  finishConstruction() {
    return this.setInputsModifiable(false).setOutputsModifiable(false);
  }
  addInput(input) {
    this.checkModifiable(fields_1.TxModifiable.INPUTS, 'Inputs');
    if (this.hasSighashSingle())
      throw new Error(
        'The Has SIGHASH_SINGLE flag is set: use addInputOutputPair',
      );
    this.pushInput(input);
    return this;
  }
  addOutput(output) {
    this.checkModifiable(fields_1.TxModifiable.OUTPUTS, 'Outputs');
    if (this.hasSighashSingle())
      throw new Error(
        'The Has SIGHASH_SINGLE flag is set: use addInputOutputPair',
      );
    this.pushOutput(output);
    return this;
  }
  /**
   * Add an input and an output at once, after the existing ones. This is the
   * only way to extend a PSTT that carries a SIGHASH_SINGLE signature: adding
   * in pairs keeps every existing input at the position of its corresponding
   * output, and keeps the added input paired with an output of its own.
   */
  addInputOutputPair(input, output) {
    this.checkModifiable(fields_1.TxModifiable.INPUTS, 'Inputs');
    this.checkModifiable(fields_1.TxModifiable.OUTPUTS, 'Outputs');
    // Appending never moves an existing input or output, so the only thing to
    // enforce is that the added input has a corresponding output.
    if (this.data.inputs.length > this.data.outputs.length)
      throw new Error(
        'The added input would have no corresponding output in a PSTT ' +
          'that contains a SIGHASH_SINGLE signature',
      );
    this.pushInput(input);
    this.pushOutput(output);
    return this;
  }
  // --- Updater ---
  /**
   * The signature hash covers the features and the locktime of the
   * transaction, so both are guarded here the way `updateInput` guards the
   * per-input locktime fields: a PSTT that already carries a signature can not
   * have either changed underneath it.
   */
  updateGlobal(update) {
    const updated = applyUpdate(
      Object.assign({}, this.data.global),
      update,
      interfaces_1.UPDATABLE_GLOBAL_KEYS,
      'the global map',
    );
    if (updated.features !== this.data.global.features && this.hasSignatures())
      throw new Error(
        'Changing the features of a PSTT that already contains signatures ' +
          'would invalidate them',
      );
    if (updated.fallbackLocktime !== this.data.global.fallbackLocktime)
      this.checkLocktimeUnchanged(
        this.data.inputs,
        'Changing the fallback locktime',
        updated.fallbackLocktime,
      );
    if (updated.txModifiable !== this.data.global.txModifiable) {
      checkTxModifiableValue(updated.txModifiable);
      this.checkModifiableTightens(updated.txModifiable);
    }
    Object.assign(this.data.global, updated);
    return this;
  }
  updateInput(inputIndex, update) {
    const input = this.checkInputIndex(inputIndex);
    const updated = applyUpdate(
      Object.assign({}, input),
      update,
      interfaces_1.UPDATABLE_INPUT_KEYS,
      `input #${inputIndex}`,
    );
    if (updated.sequence !== input.sequence)
      this.checkCanChangeSequence(inputIndex);
    if (updated.sighashType !== input.sighashType)
      this.checkCanChangeSighashType(inputIndex);
    if (
      updated.requiredTimeLocktime !== input.requiredTimeLocktime ||
      updated.requiredHeightLocktime !== input.requiredHeightLocktime
    ) {
      const candidate = this.data.inputs.slice();
      candidate[inputIndex] = updated;
      this.checkLocktimeUnchanged(candidate, 'Updating this input');
    }
    Object.assign(input, updated);
    return this;
  }
  updateOutput(outputIndex, update) {
    const output = this.checkOutputIndex(outputIndex);
    // Validated on a copy first, so that a rejected key leaves nothing applied.
    Object.assign(
      output,
      applyUpdate(
        Object.assign({}, output),
        update,
        interfaces_1.UPDATABLE_OUTPUT_KEYS,
        `output #${outputIndex}`,
      ),
    );
    return this;
  }
  // --- Transactions derived from the fields ---
  /**
   * The locktime of the transaction, resolved from
   * PSTT_GLOBAL_FALLBACK_LOCKTIME and the per-input required locktimes.
   */
  get locktime() {
    return (0, locktime_1.resolveLocktime)(
      this.data.inputs,
      this.data.global.fallbackLocktime,
    );
  }
  /**
   * The transaction the fields describe, with the real sequence numbers and
   * no scriptSigs. This is the transaction the signature hash is computed on.
   */
  getTransaction() {
    return this.buildTransaction(sequenceOf);
  }
  /**
   * The transaction that identifies this PSTT: the same fields with the
   * sequence number of every input set to 0, because sequence numbers may
   * still change after creation.
   */
  getIdentificationTransaction() {
    return this.buildTransaction(() => 0);
  }
  /**
   * The identification txid (hashMalFix), in display order.
   */
  getId() {
    return this.getIdentificationTransaction().getId();
  }
  /**
   * The output being spent by an input, taken from PSTT_IN_UTXO after
   * verifying that its txid matches PSTT_IN_PREVIOUS_TXID.
   */
  getPrevOutput(inputIndex) {
    const input = this.checkInputIndex(inputIndex);
    if (!input.utxo)
      throw new Error(`Input #${inputIndex} has no PSTT_IN_UTXO record`);
    const prevTx = transaction_1.Transaction.fromBuffer(input.utxo);
    const txid = Buffer.from(prevTx.getId(), 'hex').reverse();
    if (!txid.equals(input.previousTxid))
      throw new Error(
        `The txid of PSTT_IN_UTXO does not match PSTT_IN_PREVIOUS_TXID ` +
          `of input #${inputIndex}`,
      );
    if (input.outputIndex >= prevTx.outs.length)
      throw new Error(
        `PSTT_IN_OUTPUT_INDEX of input #${inputIndex} is out of range`,
      );
    return prevTx.outs[input.outputIndex];
  }
  /**
   * The scriptCode used in the signature hash: the redeem script for a P2SH or
   * CP2SH input, the complete scriptPubKey otherwise (including the
   * `<color identifier> OP_COLOR` prefix of a CP2PKH output).
   */
  getScriptCode(inputIndex) {
    const input = this.data.inputs[inputIndex];
    const script = this.getPrevOutput(inputIndex).script;
    const scriptType = classify.output(script);
    if (!isP2SHType(scriptType)) return script;
    if (!input.redeemScript)
      throw new Error(
        `Input #${inputIndex} spends a ${scriptType} output but has no ` +
          `PSTT_IN_REDEEM_SCRIPT record`,
      );
    if (
      !(0, crypto_1.hash160)(input.redeemScript).equals(
        scriptHashOf(script, scriptType),
      )
    )
      throw new Error(
        `The redeem script of input #${inputIndex} does not hash to the ` +
          `value committed in the scriptPubKey`,
      );
    return input.redeemScript;
  }
  hashForSignature(inputIndex, sighashType) {
    this.checkSighashType(inputIndex, sighashType);
    return this.getTransaction().hashForSignature(
      inputIndex,
      this.getScriptCode(inputIndex),
      sighashType,
    );
  }
  // --- Signer ---
  signInput(inputIndex, keyPair, opts = {}) {
    const input = this.checkInputIndex(inputIndex);
    this.checkNotFinalized(inputIndex, input);
    const sighashType = this.resolveSighashType(input, opts.sighashType);
    const scheme = opts.scheme || 'ecdsa';
    const hash = this.hashForSignature(inputIndex, sighashType);
    const signature =
      scheme === 'schnorr'
        ? Buffer.concat([
            signSchnorrWith(keyPair, hash),
            Buffer.from([sighashType]),
          ])
        : bscript.signature.encode(keyPair.sign(hash), sighashType);
    this.addPartialSig(inputIndex, {
      pubkey: keyPair.publicKey,
      signature,
    });
    return this;
  }
  /**
   * Sign every input the key belongs to. Inputs the key cannot sign, or that
   * request a sighash type this call does not produce, are skipped.
   */
  signAllInputs(keyPair, opts = {}) {
    let signed = 0;
    this.data.inputs.forEach((_, inputIndex) => {
      if (!this.inputHasPubkey(inputIndex, keyPair.publicKey)) return;
      this.signInput(inputIndex, keyPair, opts);
      signed += 1;
    });
    if (signed === 0) throw new Error('No inputs were signed by this key');
    return this;
  }
  /**
   * Record a signature, whether this instance produced it or another party did,
   * and apply the PSTT_GLOBAL_TX_MODIFIABLE updates the Signer role requires.
   * Every rule TIP-0174 places on a Signer is enforced here, so that a
   * signature imported from elsewhere cannot bypass a check `signInput` makes.
   */
  addPartialSig(inputIndex, partialSig) {
    const input = this.checkInputIndex(inputIndex);
    this.checkNotFinalized(inputIndex, input);
    if (!(0, fields_1.isValidPubkeyLength)(partialSig.pubkey))
      throw new Error(
        'A PSTT_IN_PARTIAL_SIG public key must be 33 or 65 bytes long',
      );
    const sighashType = sighashTypeOf(partialSig.signature);
    // TIP-0174 obliges a Signer to use the sighash type the input requests, so
    // a signature made with another one does not belong in this PSTT however
    // it was produced.
    if (input.sighashType !== undefined && sighashType !== input.sighashType)
      throw new Error(
        `Input #${inputIndex} requests sighash type ${input.sighashType}`,
      );
    this.checkSighashType(inputIndex, sighashType);
    // Tapyrus does not allow ECDSA and Schnorr signatures to be mixed within
    // one OP_CHECKMULTISIG evaluation.
    const scheme = signatureScheme(partialSig.signature);
    const conflicting = input.partialSig.find(
      sig => signatureScheme(sig.signature) !== scheme,
    );
    if (conflicting)
      throw new Error(
        `Input #${inputIndex} already carries a ` +
          `${signatureScheme(conflicting.signature)} signature`,
      );
    input.partialSig = input.partialSig
      .filter(sig => !sig.pubkey.equals(partialSig.pubkey))
      .concat(partialSig);
    this.applySignerModifiableRules(sighashType);
    return this;
  }
  inputHasPubkey(inputIndex, pubkey) {
    const input = this.checkInputIndex(inputIndex);
    if (input.finalScriptSig) return false;
    let script;
    try {
      script = this.getScriptCode(inputIndex);
    } catch (e) {
      return false;
    }
    return scriptInvolvesPubkey(script, pubkey);
  }
  validateSignaturesOfAllInputs() {
    if (this.data.inputs.length === 0)
      throw new Error('The PSTT has no inputs');
    return this.data.inputs.every((_, inputIndex) =>
      this.validateSignaturesOfInput(inputIndex),
    );
  }
  validateSignaturesOfInput(inputIndex, pubkey) {
    const input = this.checkInputIndex(inputIndex);
    const sigs = pubkey
      ? input.partialSig.filter(sig => sig.pubkey.equals(pubkey))
      : input.partialSig;
    if (sigs.length === 0)
      throw new Error(`No signatures to validate for input #${inputIndex}`);
    // A signature this instance did not produce still has to satisfy the rules
    // a Signer must follow. In particular a SIGHASH_SINGLE signature on an
    // input with no corresponding output covers the degenerate digest, which
    // commits to nothing, so it must never be reported as valid. Checked before
    // anything is derived from the UTXO, because the sighash type is wrong
    // whether or not the rest of the input is complete.
    //
    // A signature made with a sighash type other than the one the input
    // requests is refused for the same reason: `addPartialSig` never records
    // one, so meeting it here means the PSTT arrived contradicting itself and
    // the record covers a different transaction than the input asks for.
    for (const sig of sigs) {
      const sighashType = sighashTypeOf(sig.signature);
      this.checkSighashType(inputIndex, sighashType);
      if (input.sighashType !== undefined && sighashType !== input.sighashType)
        throw new Error(
          `Input #${inputIndex} requests sighash type ${input.sighashType} ` +
            `but carries a signature made with ${sighashType}`,
        );
    }
    const scriptCode = this.getScriptCode(inputIndex);
    // A signature is only evidence about this input if the script being
    // satisfied can be satisfied with the key that produced it. Verifying a
    // signature against a key the script never mentions reports "valid" for a
    // record that contributes nothing towards spending the output.
    for (const sig of sigs) {
      if (!scriptInvolvesPubkey(scriptCode, sig.pubkey))
        throw new Error(
          `Input #${inputIndex} carries a signature by a public key that the ` +
            `output being spent can not be satisfied with`,
        );
    }
    const tx = this.getTransaction();
    return sigs.every(sig => verifyPartialSig(tx, inputIndex, scriptCode, sig));
  }
  // --- Combiner ---
  combine(...others) {
    for (const other of others) {
      if (other.getId() !== this.getId())
        throw new Error('Can not combine PSTTs with different identifiers');
      this.checkSequencesAgree(other);
      const mine = (0, converter_1.toRaw)(this.data);
      const theirs = (0, converter_1.toRaw)(other.data);
      const merged = (0, converter_1.fromRaw)({
        global: mergeRecords(mine.global, theirs.global),
        inputs: mine.inputs.map((records, i) =>
          mergeRecords(records, theirs.inputs[i]),
        ),
        outputs: mine.outputs.map((records, i) =>
          mergeRecords(records, theirs.outputs[i]),
        ),
      });
      merged.global.txModifiable = combineModifiable(
        this.data.global.txModifiable,
        other.data.global.txModifiable,
      );
      this.data = merged;
    }
    return this;
  }
  // --- Input Finalizer ---
  /**
   * Finalize every input that is not finalized yet.
   */
  finalizeAllInputs() {
    if (this.data.inputs.length === 0)
      throw new Error('The PSTT has no inputs');
    this.data.inputs.forEach((input, inputIndex) => {
      if (!input.finalScriptSig) this.finalizeInput(inputIndex);
    });
    return this;
  }
  finalizeInput(inputIndex) {
    const input = this.checkInputIndex(inputIndex);
    if (this.isInputsModifiable() || this.isOutputsModifiable())
      throw new Error(
        'A PSTT must not be finalized while it is still modifiable',
      );
    if (input.finalScriptSig)
      throw new Error(`Input #${inputIndex} is already finalized`);
    input.finalScriptSig = this.buildFinalScriptSig(inputIndex);
    // Everything that was only needed to collect signatures is dropped; the
    // outpoint, sequence, locktime, UTXO and unknown records are kept.
    input.partialSig = [];
    input.bip32Derivation = [];
    input.ripemd160Preimages = {};
    input.sha256Preimages = {};
    input.hash160Preimages = {};
    input.hash256Preimages = {};
    delete input.sighashType;
    delete input.redeemScript;
    return this;
  }
  // --- Transaction Extractor ---
  extractTransaction() {
    const tx = this.getTransaction();
    this.data.inputs.forEach((input, inputIndex) => {
      if (!input.finalScriptSig)
        throw new Error(
          `Input #${inputIndex} has no PSTT_IN_FINAL_SCRIPTSIG record`,
        );
      tx.setInputScript(inputIndex, input.finalScriptSig);
    });
    return tx;
  }
  // --- Serialization ---
  toBuffer() {
    return (0, container_1.encode)((0, converter_1.toRaw)(this.data));
  }
  toBase64() {
    return this.toBuffer().toString('base64');
  }
  toHex() {
    return this.toBuffer().toString('hex');
  }
  // --- Internals ---
  buildTransaction(sequenceFor) {
    const tx = new transaction_1.Transaction();
    tx.version = this.data.global.features;
    tx.locktime = this.locktime;
    for (const input of this.data.inputs) {
      tx.addInput(input.previousTxid, input.outputIndex, sequenceFor(input));
    }
    for (const output of this.data.outputs) {
      tx.addOutput(output.script, output.amount);
    }
    return tx;
  }
  buildFinalScriptSig(inputIndex) {
    const input = this.data.inputs[inputIndex];
    const script = this.getPrevOutput(inputIndex).script;
    const isP2SH = isP2SHType(classify.output(script));
    const meaningful = this.getScriptCode(inputIndex);
    const scriptType = classify.output(meaningful);
    const builder = (0, finalizer_1.scriptSigBuilderFor)(scriptType);
    if (!builder)
      throw new Error(
        `Can not finalize input #${inputIndex}: unsupported script type ` +
          `${scriptType}`,
      );
    // TIP-0174 has the Input Finalizer check that "the collected records are
    // sufficient to satisfy the script", and a record that does not verify is
    // not. Handing the builders only the signatures that do makes the check
    // theirs to complete: each already refuses to build when too few are left.
    //
    // The multisig builder is why this matters. It takes the first m public
    // keys of the script that carry a record, so one bad signature among m+1
    // otherwise good ones would displace a good one and yield a scriptSig that
    // fails at validation, with the signatures needed to spend the output
    // sitting unused in the same input.
    const tx = this.getTransaction();
    const partialSig = input.partialSig.filter(sig =>
      verifyPartialSig(tx, inputIndex, meaningful, sig),
    );
    const stack = builder({ inputIndex, script: meaningful, partialSig });
    if (isP2SH) stack.push(meaningful);
    return bscript.compile(stack);
  }
  pushInput(add) {
    const { previousTxid, outputIndex } = add,
      update = __rest(add, ['previousTxid', 'outputIndex']);
    const txid =
      typeof previousTxid === 'string'
        ? Buffer.from(previousTxid, 'hex').reverse()
        : previousTxid;
    if (txid.length !== 32) throw new Error('previousTxid must be 32 bytes');
    const added = applyUpdate(
      emptyInput(),
      update,
      interfaces_1.UPDATABLE_INPUT_KEYS,
      'a new input',
    );
    added.previousTxid = txid;
    added.outputIndex = outputIndex;
    this.checkLocktimeUnchanged(
      this.data.inputs.concat(added),
      'Adding this input',
    );
    this.data.inputs.push(added);
  }
  pushOutput(add) {
    const { amount, script, address } = add,
      update = __rest(add, ['amount', 'script', 'address']);
    const outputScript =
      script ||
      (address
        ? (0, address_1.toOutputScript)(address, this.opts.network)
        : undefined);
    if (!outputScript)
      throw new Error('An output needs a script or an address');
    const added = applyUpdate(
      emptyOutput(),
      update,
      interfaces_1.UPDATABLE_OUTPUT_KEYS,
      'a new output',
    );
    added.script = outputScript;
    added.amount = amount;
    this.data.outputs.push(added);
  }
  /**
   * TIP-0174 treats an absent PSTT_GLOBAL_TX_MODIFIABLE as "not modifiable", so
   * a Constructor may only add while the corresponding flag is set. A PSTT this
   * process created starts with both flags set (see `emptyData`), which is what
   * lets a Creator build one before deciding to fix it.
   */
  checkModifiable(flag, name) {
    if (!this.hasModifiableFlag(flag))
      throw new Error(`The ${name} Modifiable flag is not set`);
  }
  /**
   * An Updater must not change the sequence number of a signed input, nor of
   * any input while some SIGHASH_ALL signature (without SIGHASH_ANYONECANPAY)
   * commits to it.
   *
   * A finalized input counts as signed even though its PSTT_IN_PARTIAL_SIG
   * records are gone: the signatures moved into PSTT_IN_FINAL_SCRIPTSIG, where
   * their sighash types are no longer readable as records. Which of them commit
   * to which sequence number can therefore no longer be decided, so any
   * finalized input blocks every sequence change in the PSTT.
   */
  checkCanChangeSequence(inputIndex) {
    const target = this.data.inputs[inputIndex];
    if (target.partialSig.length > 0 || target.finalScriptSig)
      throw new Error(
        `Input #${inputIndex} is signed: its sequence number is committed to`,
      );
    for (const input of this.data.inputs) {
      if (input.finalScriptSig)
        throw new Error(
          'A finalized input carries signatures that may commit to the ' +
            'sequence number of every input of this PSTT',
        );
      for (const sig of input.partialSig) {
        if (
          sighashTypeOf(sig.signature) === transaction_1.Transaction.SIGHASH_ALL
        )
          throw new Error(
            'A SIGHASH_ALL signature commits to the sequence number of ' +
              'every input of this PSTT',
          );
      }
    }
  }
  /**
   * TIP-0174 requires every signature of an input to use the sighash type
   * PSTT_IN_SIGHASH_TYPE requests, so an Updater that changes the request once
   * the input holds a signature leaves the input contradicting itself — and
   * `addPartialSig`, which enforces the same rule from the Signer's side, would
   * then reject the very signatures already recorded.
   *
   * A finalized input counts as signed: its signatures moved into
   * PSTT_IN_FINAL_SCRIPTSIG, and the Input Finalizer removed the record this
   * would recreate.
   */
  checkCanChangeSighashType(inputIndex) {
    const input = this.data.inputs[inputIndex];
    if (input.partialSig.length > 0 || input.finalScriptSig)
      throw new Error(
        `Input #${inputIndex} is signed: its signatures commit to the sighash ` +
          `type it requests`,
      );
  }
  /**
   * TIP-0174 lets a Combiner resolve a conflicting record by keeping either
   * value, and `mergeRecords` keeps this copy's. PSTT_IN_SEQUENCE is the one
   * record where that silently destroys information: the identification txid is
   * computed with every sequence number set to 0, so two copies that disagree
   * about one still identify as the same PSTT, and keeping this copy's value
   * would invalidate every signature of the other copy that commits to the
   * other one. This is therefore the conflict the Combiner refuses rather than
   * resolves.
   */
  checkSequencesAgree(other) {
    this.data.inputs.forEach((input, inputIndex) => {
      if (sequenceOf(input) !== sequenceOf(other.data.inputs[inputIndex]))
        throw new Error(
          `Input #${inputIndex} has a different sequence number in the two ` +
            `PSTTs`,
        );
    });
  }
  /**
   * Every signature commits to the locktime, so neither a Constructor nor an
   * Updater may change the locktime a PSTT resolves to once it holds one.
   */
  checkLocktimeUnchanged(
    candidate,
    action,
    fallbackLocktime = this.data.global.fallbackLocktime,
  ) {
    if (!this.hasSignatures()) return;
    if (locktimeOrNaN(candidate, fallbackLocktime) !== this.locktime)
      throw new Error(
        `${action} would change the locktime of a PSTT that ` +
          'already contains signatures',
      );
  }
  checkSighashType(inputIndex, sighashType) {
    if (!(0, fields_1.isValidSighashType)(sighashType))
      throw new Error(`Invalid sighash type ${sighashType}`);
    if (
      (sighashType & ~transaction_1.Transaction.SIGHASH_ANYONECANPAY) ===
        transaction_1.Transaction.SIGHASH_SINGLE &&
      inputIndex >= this.data.outputs.length
    )
      throw new Error(
        `Input #${inputIndex} has no corresponding output and must not be ` +
          `signed with SIGHASH_SINGLE`,
      );
    // Throws when the required locktimes of the inputs contradict each other,
    // in which case no signature can be produced over a valid transaction.
    (0, locktime_1.resolveLocktime)(
      this.data.inputs,
      this.data.global.fallbackLocktime,
    );
  }
  resolveSighashType(input, requested) {
    if (input.sighashType === undefined)
      return requested === undefined
        ? transaction_1.Transaction.SIGHASH_ALL
        : requested;
    if (requested !== undefined && requested !== input.sighashType)
      throw new Error(`This input requests sighash type ${input.sighashType}`);
    return input.sighashType;
  }
  applySignerModifiableRules(sighashType) {
    const base = sighashType & ~transaction_1.Transaction.SIGHASH_ANYONECANPAY;
    if (!(sighashType & transaction_1.Transaction.SIGHASH_ANYONECANPAY))
      this.setModifiableFlag(fields_1.TxModifiable.INPUTS, false);
    if (base !== transaction_1.Transaction.SIGHASH_NONE)
      this.setModifiableFlag(fields_1.TxModifiable.OUTPUTS, false);
    if (base === transaction_1.Transaction.SIGHASH_SINGLE)
      this.setModifiableFlag(fields_1.TxModifiable.HAS_SIGHASH_SINGLE, true);
  }
  setModifiableFlag(flag, set) {
    const current = this.data.global.txModifiable;
    // An absent field already means "not modifiable"; do not create one only
    // to clear a flag.
    if (current === undefined && !set) return this;
    const next = set ? (current || 0) | flag : (current || 0) & ~flag;
    // `flag` is a defined bit, so `next` can only carry a reserved one that
    // `current` already had — which reaching this far means came from a
    // hand-built `PsttData` rather than from a parsed or updated PSTT.
    checkTxModifiableValue(next);
    this.checkModifiableTightens(next);
    this.data.global.txModifiable = next;
    return this;
  }
  /**
   * PSTT_GLOBAL_TX_MODIFIABLE records what the signatures collected so far
   * still allow, so once a PSTT holds one, a change to the field may only
   * tighten it. Setting Inputs Modifiable or Outputs Modifiable again would
   * re-open the very modification a Signer closed by signing, and clearing Has
   * SIGHASH_SINGLE would drop the pairing rule that keeps a SIGHASH_SINGLE
   * signature covering its own output — either way `addInput`, `addOutput` and
   * `finalizeInput`, which all consult this field, would let through a change
   * that invalidates the existing signatures.
   */
  checkModifiableTightens(next) {
    if (!this.hasSignatures()) return;
    const before = this.data.global.txModifiable || 0;
    const after = next || 0;
    const loosened =
      (after &
        ~before &
        (fields_1.TxModifiable.INPUTS | fields_1.TxModifiable.OUTPUTS)) |
      (before & ~after & fields_1.TxModifiable.HAS_SIGHASH_SINGLE);
    if (loosened !== 0)
      throw new Error(
        'Relaxing PSTT_GLOBAL_TX_MODIFIABLE on a PSTT that already contains ' +
          'signatures would invalidate them',
      );
  }
  hasModifiableFlag(flag) {
    return ((this.data.global.txModifiable || 0) & flag) !== 0;
  }
  hasSignatures() {
    return this.data.inputs.some(
      input =>
        input.partialSig.length > 0 || input.finalScriptSig !== undefined,
    );
  }
  /**
   * The Input Finalizer removes the PSTT_IN_PARTIAL_SIG records of an input it
   * finalizes, so a signature added afterwards would recreate a record the
   * format says is no longer there, next to the finalized scriptSig.
   */
  checkNotFinalized(inputIndex, input) {
    if (input.finalScriptSig)
      throw new Error(
        `Input #${inputIndex} is finalized and takes no further signature`,
      );
  }
  checkInputIndex(inputIndex) {
    const input = this.data.inputs[inputIndex];
    if (!input) throw new Error(`No input #${inputIndex}`);
    return input;
  }
  checkOutputIndex(outputIndex) {
    const output = this.data.outputs[outputIndex];
    if (!output) throw new Error(`No output #${outputIndex}`);
    return output;
  }
}
exports.Pstt = Pstt;
function signSchnorrWith(keyPair, hash) {
  let signature;
  if (keyPair.signSchnorr) signature = keyPair.signSchnorr(hash);
  else if (keyPair.privateKey)
    signature = schnorr.sign(keyPair.privateKey, hash);
  else throw new Error('This signer can not produce Schnorr signatures');
  // The scheme of a PSTT_IN_PARTIAL_SIG value is decided by its length alone,
  // so a signer returning any other size would silently produce a record that
  // the script interpreter — and `signatureScheme` — read as ECDSA.
  if (signature.length !== SCHNORR_RAW_SIGNATURE_LENGTH)
    throw new Error(
      `A Schnorr signer must return ${SCHNORR_RAW_SIGNATURE_LENGTH} bytes, ` +
        `got ${signature.length}`,
    );
  return signature;
}
/**
 * A PSTT this process is creating. Both modifiable flags start set, so that a
 * Creator can add inputs and outputs; `finishConstruction` clears them. A PSTT
 * parsed from bytes keeps whatever PSTT_GLOBAL_TX_MODIFIABLE it carries, and an
 * absent field means "not modifiable" as TIP-0174 requires.
 */
function emptyData() {
  return {
    global: {
      xpub: [],
      features: DEFAULT_FEATURES,
      txModifiable:
        fields_1.TxModifiable.INPUTS | fields_1.TxModifiable.OUTPUTS,
      unknownKeyVals: [],
    },
    inputs: [],
    outputs: [],
  };
}
function emptyInput() {
  return {
    partialSig: [],
    bip32Derivation: [],
    ripemd160Preimages: {},
    sha256Preimages: {},
    hash160Preimages: {},
    hash256Preimages: {},
    previousTxid: Buffer.alloc(32),
    outputIndex: 0,
    unknownKeyVals: [],
  };
}
function emptyOutput() {
  return {
    bip32Derivation: [],
    amount: 0,
    script: Buffer.alloc(0),
    unknownKeyVals: [],
  };
}
