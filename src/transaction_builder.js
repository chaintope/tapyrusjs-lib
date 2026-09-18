'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.TransactionBuilder = void 0;
const baddress = require('./address');
const bufferutils_1 = require('./bufferutils');
const classify = require('./classify');
const bcrypto = require('./crypto');
const ECPair = require('./ecpair');
const networks = require('./networks');
const payments = require('./payments');
const bscript = require('./script');
const script_1 = require('./script');
const transaction_1 = require('./transaction');
const types = require('./types');
const typeforce = require('typeforce');
const SCRIPT_TYPES = classify.types;
const PREVOUT_TYPES = new Set([
  // Raw
  'p2pkh',
  'p2pk',
  'p2ms',
  // Colored
  'cp2pkh',
  'cp2sh',
  // P2SH wrapped
  'p2sh-p2pkh',
  'p2sh-p2pk',
  'p2sh-p2ms',
]);
/** The output type of a script, or undefined when it can not be parsed. */
function outputTypeOf(script) {
  if (!script) return undefined;
  try {
    return classify.output(script);
  } catch (e) {
    return undefined;
  }
}
function isColoredScript(script) {
  const type = outputTypeOf(script);
  return type === SCRIPT_TYPES.CP2PKH || type === SCRIPT_TYPES.CP2SH;
}
function tfMessage(type, value, message) {
  try {
    typeforce(type, value);
  } catch (err) {
    throw new Error(message);
  }
}
function txIsString(tx) {
  return typeof tx === 'string' || tx instanceof String;
}
function txIsTransaction(tx) {
  return tx instanceof transaction_1.Transaction;
}
class TransactionBuilder {
  static fromTransaction(transaction, network) {
    const txb = new TransactionBuilder(network);
    // Copy transaction fields
    txb.setVersion(transaction.version);
    txb.setLockTime(transaction.locktime);
    // Copy outputs (done first to avoid signature invalidation)
    transaction.outs.forEach(txOut => {
      txb.addOutput(txOut.script, txOut.value);
    });
    // Copy inputs
    transaction.ins.forEach(txIn => {
      txb.__addInputUnsafe(txIn.hash, txIn.index, {
        sequence: txIn.sequence,
        script: txIn.script,
      });
    });
    // fix some things not possible through the public API
    txb.__INPUTS.forEach((input, i) => {
      fixMultisigOrder(input, transaction, i);
    });
    return txb;
  }
  // WARNING: maximumFeeRate is __NOT__ to be relied on,
  //          it's just another potential safety mechanism (safety in-depth)
  constructor(network = networks.prod, maximumFeeRate = 2500) {
    this.network = network;
    this.maximumFeeRate = maximumFeeRate;
    this.__PREV_TX_SET = {};
    this.__INPUTS = [];
    this.__TX = new transaction_1.Transaction();
    this.__TX.version = 2;
    this.__USE_LOW_R = false;
    console.warn(
      'Deprecation Warning: TransactionBuilder will be removed in the future. ' +
        '(v6.x.x or later) Please use the Psbt class instead. Examples of usage ' +
        'are available in the transactions-psbt.js integration test file on our ' +
        'Github. A high level explanation is available in the psbt.ts and psbt.js ' +
        'files as well.',
    );
  }
  setLowR(setting) {
    typeforce(typeforce.maybe(typeforce.Boolean), setting);
    if (setting === undefined) {
      setting = true;
    }
    this.__USE_LOW_R = setting;
    return setting;
  }
  setLockTime(locktime) {
    typeforce(types.UInt32, locktime);
    // if any signatures exist, throw
    if (
      this.__INPUTS.some(input => {
        if (!input.signatures) return false;
        return input.signatures.some(s => s !== undefined);
      })
    ) {
      throw new Error('No, this would invalidate signatures');
    }
    this.__TX.locktime = locktime;
  }
  setVersion(version) {
    typeforce(types.UInt32, version);
    // XXX: this might eventually become more complex depending on what the versions represent
    this.__TX.version = version;
  }
  addInput(txHash, vout, sequence, prevOutScript) {
    if (!this.__canModifyInputs()) {
      throw new Error('No, this would invalidate signatures');
    }
    let value;
    // is it a hex string?
    if (txIsString(txHash)) {
      // transaction hashs's are displayed in reverse order, un-reverse it
      txHash = (0, bufferutils_1.reverseBuffer)(Buffer.from(txHash, 'hex'));
      // is it a Transaction object?
    } else if (txIsTransaction(txHash)) {
      const txOut = txHash.outs[vout];
      if (!txOut) throw new Error('No output at index: ' + vout);
      prevOutScript = txOut.script;
      value = txOut.value;
      txHash = txHash.getMalFixHash();
    }
    return this.__addInputUnsafe(txHash, vout, {
      sequence,
      prevOutScript,
      value,
    });
  }
  addOutput(scriptPubKey, value) {
    if (!this.__canModifyOutputs()) {
      throw new Error('No, this would invalidate signatures');
    }
    // Attempt to get a script if it's a base58 address string
    if (typeof scriptPubKey === 'string') {
      scriptPubKey = baddress.toOutputScript(scriptPubKey, this.network);
    }
    return this.__TX.addOutput(scriptPubKey, value);
  }
  build() {
    return this.__build(false);
  }
  buildIncomplete() {
    return this.__build(true);
  }
  sign(signParams, keyPair, redeemScript, hashType) {
    trySign(
      getSigningData(
        this.network,
        this.__INPUTS,
        this.__needsOutputs.bind(this),
        this.__TX,
        signParams,
        keyPair,
        redeemScript,
        hashType,
        this.__USE_LOW_R,
      ),
    );
  }
  __addInputUnsafe(txHash, vout, options) {
    if (transaction_1.Transaction.isCoinbaseHash(txHash)) {
      throw new Error('coinbase inputs not supported');
    }
    const prevTxOut = txHash.toString('hex') + ':' + vout;
    if (this.__PREV_TX_SET[prevTxOut] !== undefined)
      throw new Error('Duplicate TxOut: ' + prevTxOut);
    let input = {};
    // derive what we can from the scriptSig
    if (options.script !== undefined) {
      input = expandInput(options.script);
    }
    // if an input value was given, retain it
    if (options.value !== undefined) {
      input.value = options.value;
    }
    // derive what we can from the previous transactions output script
    if (!input.prevOutScript && options.prevOutScript) {
      let prevOutType;
      if (!input.pubkeys && !input.signatures) {
        const expanded = expandOutput(options.prevOutScript);
        if (expanded.pubkeys) {
          input.pubkeys = expanded.pubkeys;
          input.signatures = expanded.signatures;
        }
        prevOutType = expanded.type;
      }
      input.prevOutScript = options.prevOutScript;
      input.prevOutType = prevOutType || classify.output(options.prevOutScript);
    }
    const vin = this.__TX.addInput(
      txHash,
      vout,
      options.sequence,
      options.scriptSig,
    );
    this.__INPUTS[vin] = input;
    this.__PREV_TX_SET[prevTxOut] = true;
    return vin;
  }
  __build(allowIncomplete) {
    if (!allowIncomplete) {
      if (!this.__TX.ins.length) throw new Error('Transaction has no inputs');
      if (!this.__TX.outs.length) throw new Error('Transaction has no outputs');
    }
    const tx = this.__TX.clone();
    // create script signatures from inputs
    this.__INPUTS.forEach((input, i) => {
      if (!input.prevOutType && !allowIncomplete)
        throw new Error('Transaction is not complete');
      const result = build(input.prevOutType, input, allowIncomplete);
      if (!result) {
        if (!allowIncomplete && input.prevOutType === SCRIPT_TYPES.NONSTANDARD)
          throw new Error('Unknown input type');
        if (!allowIncomplete) throw new Error('Not enough information');
        return;
      }
      tx.setInputScript(i, result.input);
    });
    if (!allowIncomplete) {
      // do not rely on this, its merely a last resort
      if (this.__overMaximumFees(tx.byteLength())) {
        throw new Error('Transaction has absurd fees');
      }
    }
    return tx;
  }
  __canModifyInputs() {
    return this.__INPUTS.every(input => {
      if (!input.signatures) return true;
      return input.signatures.every(signature => {
        if (!signature) return true;
        const hashType = signatureHashType(signature);
        // if SIGHASH_ANYONECANPAY is set, signatures would not
        // be invalidated by more inputs
        return (
          (hashType & transaction_1.Transaction.SIGHASH_ANYONECANPAY) !== 0
        );
      });
    });
  }
  __needsOutputs(signingHashType) {
    if (signingHashType === transaction_1.Transaction.SIGHASH_ALL) {
      return this.__TX.outs.length === 0;
    }
    // if inputs are being signed with SIGHASH_NONE, we don't strictly need outputs
    // .build() will fail, but .buildIncomplete() is OK
    return (
      this.__TX.outs.length === 0 &&
      this.__INPUTS.some(input => {
        if (!input.signatures) return false;
        return input.signatures.some(signature => {
          if (!signature) return false; // no signature, no issue
          const hashType = signatureHashType(signature);
          if (hashType & transaction_1.Transaction.SIGHASH_NONE) return false; // SIGHASH_NONE doesn't care about outputs
          return true; // SIGHASH_* does care
        });
      })
    );
  }
  __canModifyOutputs() {
    const nInputs = this.__TX.ins.length;
    const nOutputs = this.__TX.outs.length;
    return this.__INPUTS.every(input => {
      if (input.signatures === undefined) return true;
      return input.signatures.every(signature => {
        if (!signature) return true;
        const hashType = signatureHashType(signature);
        const hashTypeMod = hashType & 0x1f;
        if (hashTypeMod === transaction_1.Transaction.SIGHASH_NONE) return true;
        if (hashTypeMod === transaction_1.Transaction.SIGHASH_SINGLE) {
          // if SIGHASH_SINGLE is set, and nInputs > nOutputs
          // some signatures would be invalidated by the addition
          // of more outputs
          return nInputs <= nOutputs;
        }
        return false;
      });
    });
  }
  __overMaximumFees(bytes) {
    // A coloured input or output carries a token amount, not TPC, so it must
    // not enter the fee calculation. Inputs without a known value count as 0.
    const incoming = this.__INPUTS.reduce(
      (a, x) => (isColoredScript(x.prevOutScript) ? a : a + (x.value || 0)),
      0,
    );
    const outgoing = this.__TX.outs.reduce(
      (a, x) => (isColoredScript(x.script) ? a : a + x.value),
      0,
    );
    const fee = incoming - outgoing;
    const feeRate = fee / bytes;
    return feeRate > this.maximumFeeRate;
  }
}
exports.TransactionBuilder = TransactionBuilder;
function expandInput(scriptSig, type, scriptPubKey) {
  if (scriptSig.length === 0) return {};
  if (!type) {
    const ssType = classify.input(scriptSig, true);
    if (ssType !== SCRIPT_TYPES.NONSTANDARD) type = ssType;
  }
  switch (type) {
    case SCRIPT_TYPES.P2PKH: {
      const { output, pubkey, signature } = payments.p2pkh({
        input: scriptSig,
      });
      return {
        prevOutScript: output,
        prevOutScriptInferred: true,
        prevOutType: SCRIPT_TYPES.P2PKH,
        pubkeys: [pubkey],
        signatures: [signature],
      };
    }
    case SCRIPT_TYPES.P2PK: {
      const { signature } = payments.p2pk({ input: scriptSig });
      return {
        prevOutType: SCRIPT_TYPES.P2PK,
        pubkeys: [undefined],
        signatures: [signature],
      };
    }
    case SCRIPT_TYPES.P2MS: {
      const { m, pubkeys, signatures } = payments.p2ms(
        {
          input: scriptSig,
          output: scriptPubKey,
        },
        { allowIncomplete: true },
      );
      return {
        prevOutType: SCRIPT_TYPES.P2MS,
        pubkeys,
        signatures,
        maxSignatures: m,
      };
    }
  }
  if (type === SCRIPT_TYPES.P2SH) {
    const { output, redeem } = payments.p2sh({
      input: scriptSig,
    });
    const outputType = classify.output(redeem.output);
    const expanded = expandInput(redeem.input, outputType, redeem.output);
    if (!expanded.prevOutType) return {};
    return {
      prevOutScript: output,
      prevOutScriptInferred: true,
      prevOutType: SCRIPT_TYPES.P2SH,
      redeemScript: redeem.output,
      redeemScriptType: expanded.prevOutType,
      pubkeys: expanded.pubkeys,
      signatures: expanded.signatures,
    };
  }
  return {
    prevOutType: SCRIPT_TYPES.NONSTANDARD,
    prevOutScript: scriptSig,
  };
}
// could be done in expandInput, but requires the original Transaction for hashForSignature
function fixMultisigOrder(input, transaction, vin) {
  if (input.redeemScriptType !== SCRIPT_TYPES.P2MS || !input.redeemScript)
    return;
  if (input.pubkeys.length === input.signatures.length) return;
  const unmatched = input.signatures.concat();
  input.signatures = input.pubkeys.map(pubKey => {
    const keyPair = ECPair.fromPublicKey(pubKey);
    let match;
    // check for a signature
    unmatched.some((signature, i) => {
      // skip if undefined || OP_0
      if (!signature) return false;
      // TODO: avoid O(n) hashForSignature
      const parsed = bscript.signature.decode(signature);
      const hash = transaction.hashForSignature(
        vin,
        input.redeemScript,
        parsed.hashType,
      );
      // skip if signature does not match pubKey
      if (!keyPair.verify(hash, parsed.signature)) return false;
      // remove matched signature from unmatched
      unmatched[i] = undefined;
      match = signature;
      return true;
    });
    return match;
  });
}
function expandOutput(script, ourPubKey) {
  typeforce(types.Buffer, script);
  const type = classify.output(script);
  switch (type) {
    case SCRIPT_TYPES.P2PKH: {
      if (!ourPubKey) return { type };
      // does our hash160(pubKey) match the output scripts?
      const pkh1 = payments.p2pkh({ output: script }).hash;
      const pkh2 = bcrypto.hash160(ourPubKey);
      if (!pkh1.equals(pkh2)) return { type };
      return {
        type,
        pubkeys: [ourPubKey],
        signatures: [undefined],
      };
    }
    case SCRIPT_TYPES.P2PK: {
      const p2pk = payments.p2pk({ output: script });
      return {
        type,
        pubkeys: [p2pk.pubkey],
        signatures: [undefined],
      };
    }
    case SCRIPT_TYPES.P2MS: {
      const p2ms = payments.p2ms({ output: script });
      return {
        type,
        pubkeys: p2ms.pubkeys,
        signatures: p2ms.pubkeys.map(() => undefined),
        maxSignatures: p2ms.m,
      };
    }
    case SCRIPT_TYPES.CP2PKH: {
      if (!ourPubKey) return { type };
      // does our hash160(pubKey) match the output scripts?
      const pkh1 = payments.cp2pkh({ output: script }).hash;
      const pkh2 = bcrypto.hash160(ourPubKey);
      if (!pkh1.equals(pkh2)) return { type };
      return {
        type,
        pubkeys: [ourPubKey],
        signatures: [undefined],
      };
    }
  }
  return { type };
}
function prepareInput(input, ourPubKey, redeemScript, prevOutScriptType) {
  if (redeemScript) {
    // A CP2SH prevOutScript wraps the same redeem script, but the scriptPubKey
    // carries the colour identifier, so it must be rebuilt as CP2SH.
    const prevOut = input.prevOutScript;
    const knownColored = outputTypeOf(prevOut) === SCRIPT_TYPES.CP2SH;
    // The colour only exists in the output being spent. When that output is
    // unknown, the caller saying cp2sh is the only thing that identifies it.
    const colored =
      knownColored || (prevOut === undefined && prevOutScriptType === 'cp2sh');
    let alt;
    if (prevOut) {
      try {
        alt = knownColored
          ? payments.cp2sh({ output: prevOut })
          : payments.p2sh({ output: prevOut });
      } catch (e) {
        throw new Error('PrevOutScript must be P2SH');
      }
    }
    const payment = knownColored
      ? payments.cp2sh({
          redeem: { output: redeemScript },
          colorId: alt.colorId,
        })
      : payments.p2sh({ redeem: { output: redeemScript } });
    if (alt && !payment.hash.equals(alt.hash))
      throw new Error('Redeem script inconsistent with prevOutScript');
    const expanded = expandOutput(payment.redeem.output, ourPubKey);
    if (!expanded.pubkeys)
      throw new Error(
        expanded.type +
          ' not supported as redeemScript (' +
          bscript.toASM(redeemScript) +
          ')',
      );
    if (input.signatures && input.signatures.some(x => x !== undefined)) {
      expanded.signatures = input.signatures;
    }
    const signScript = redeemScript;
    return {
      redeemScript,
      redeemScriptType: expanded.type,
      prevOutType: colored ? SCRIPT_TYPES.CP2SH : SCRIPT_TYPES.P2SH,
      // without the colour the CP2SH scriptPubKey can not be rebuilt, and a
      // P2SH one would be a lie
      prevOutScript: colored && !knownColored ? undefined : payment.output,
      signScript,
      signType: expanded.type,
      pubkeys: expanded.pubkeys,
      signatures: expanded.signatures,
      maxSignatures: expanded.maxSignatures,
    };
  }
  if (input.prevOutType && input.prevOutScript) {
    // embedded scripts are not possible without extra information
    if (
      input.prevOutType === SCRIPT_TYPES.P2SH ||
      input.prevOutType === SCRIPT_TYPES.CP2SH
    )
      throw new Error(
        'PrevOutScript is ' + input.prevOutType + ', requires redeemScript',
      );
    if (!input.prevOutScript) throw new Error('PrevOutScript is missing');
    const expanded = expandOutput(input.prevOutScript, ourPubKey);
    if (!expanded.pubkeys)
      throw new Error(
        expanded.type +
          ' not supported (' +
          bscript.toASM(input.prevOutScript) +
          ')',
      );
    if (input.signatures && input.signatures.some(x => x !== undefined)) {
      expanded.signatures = input.signatures;
    }
    const signScript = input.prevOutScript;
    return {
      prevOutType: expanded.type,
      prevOutScript: input.prevOutScript,
      signScript,
      signType: expanded.type,
      pubkeys: expanded.pubkeys,
      signatures: expanded.signatures,
      maxSignatures: expanded.maxSignatures,
    };
  }
  const prevOutScript = payments.p2pkh({ pubkey: ourPubKey }).output;
  return {
    prevOutType: SCRIPT_TYPES.P2PKH,
    prevOutScript,
    signScript: prevOutScript,
    signType: SCRIPT_TYPES.P2PKH,
    pubkeys: [ourPubKey],
    signatures: [undefined],
  };
}
function build(type, input, allowIncomplete) {
  const pubkeys = input.pubkeys || [];
  let signatures = input.signatures || [];
  switch (type) {
    case SCRIPT_TYPES.P2PKH: {
      if (pubkeys.length === 0) break;
      if (signatures.length === 0) break;
      return payments.p2pkh({ pubkey: pubkeys[0], signature: signatures[0] });
    }
    case SCRIPT_TYPES.P2PK: {
      if (pubkeys.length === 0) break;
      if (signatures.length === 0) break;
      return payments.p2pk({ signature: signatures[0] });
    }
    case SCRIPT_TYPES.P2MS: {
      const m = input.maxSignatures;
      if (allowIncomplete) {
        signatures = signatures.map(x => x || script_1.OPS.OP_0);
      } else {
        signatures = signatures.filter(x => x);
      }
      // if the transaction is not not complete (complete), or if signatures.length === m, validate
      // otherwise, the number of OP_0's may be >= m, so don't validate (boo)
      const validate = !allowIncomplete || m === signatures.length;
      return payments.p2ms(
        { m, pubkeys, signatures },
        { allowIncomplete, validate },
      );
    }
    case SCRIPT_TYPES.P2SH: {
      const redeem = build(input.redeemScriptType, input, allowIncomplete);
      if (!redeem) return;
      return payments.p2sh({
        redeem: {
          output: redeem.output || input.redeemScript,
          input: redeem.input,
        },
      });
    }
    case SCRIPT_TYPES.CP2PKH: {
      if (pubkeys.length === 0) break;
      if (signatures.length === 0) break;
      return payments.cp2pkh({
        pubkey: pubkeys[0],
        signature: signatures[0],
      });
    }
    case SCRIPT_TYPES.CP2SH: {
      const redeem = build(input.redeemScriptType, input, allowIncomplete);
      if (!redeem) return;
      return payments.cp2sh({
        redeem: {
          output: redeem.output || input.redeemScript,
          input: redeem.input,
        },
      });
    }
  }
}
function canSign(input) {
  return (
    input.signScript !== undefined &&
    input.signType !== undefined &&
    input.pubkeys !== undefined &&
    input.signatures !== undefined &&
    input.signatures.length === input.pubkeys.length &&
    input.pubkeys.length > 0
  );
}
function signatureHashType(buffer) {
  return buffer.readUInt8(buffer.length - 1);
}
function checkSignArgs(inputs, signParams) {
  if (!PREVOUT_TYPES.has(signParams.prevOutScriptType)) {
    throw new TypeError(
      `Unknown prevOutScriptType "${signParams.prevOutScriptType}"`,
    );
  }
  tfMessage(
    typeforce.Number,
    signParams.vin,
    `sign must include vin parameter as Number (input index)`,
  );
  tfMessage(
    types.Signer,
    signParams.keyPair,
    `sign must include keyPair parameter as Signer interface`,
  );
  tfMessage(
    typeforce.maybe(typeforce.Number),
    signParams.hashType,
    `sign hashType parameter must be a number`,
  );
  const input = inputs[signParams.vin] || {};
  const prevOutType = input.prevOutType;
  const posType = signParams.prevOutScriptType;
  if (
    (posType === 'cp2pkh' || posType === 'cp2sh') &&
    input.prevOutScriptInferred
  ) {
    // A coloured scriptPubKey can not be recovered from a scriptSig: the
    // colour identifier only appears in the output being spent. Signing
    // against the guessed script would commit to the wrong script code.
    throw new TypeError(
      `input #${signParams.vin} was restored from a transaction, so its ` +
        `previous output script is a guess. Rebuild the transaction with ` +
        `addInput(txid, vout, sequence, prevOutScript) to sign a coloured ` +
        `input.`,
    );
  }
  switch (posType) {
    case 'p2pkh':
      if (prevOutType && prevOutType !== 'pubkeyhash') {
        throw new TypeError(
          `input #${signParams.vin} is not of type p2pkh: ${prevOutType}`,
        );
      }
      tfMessage(
        typeforce.value(undefined),
        signParams.redeemScript,
        `${posType} requires NO redeemScript`,
      );
      break;
    case 'p2pk':
      if (prevOutType && prevOutType !== 'pubkey') {
        throw new TypeError(
          `input #${signParams.vin} is not of type p2pk: ${prevOutType}`,
        );
      }
      tfMessage(
        typeforce.value(undefined),
        signParams.redeemScript,
        `${posType} requires NO redeemScript`,
      );
      break;
    case 'p2ms':
      if (prevOutType && prevOutType !== 'multisig') {
        throw new TypeError(
          `input #${signParams.vin} is not of type p2ms: ${prevOutType}`,
        );
      }
      tfMessage(
        typeforce.value(undefined),
        signParams.redeemScript,
        `${posType} requires NO redeemScript`,
      );
      break;
    case 'p2sh-p2ms':
    case 'p2sh-p2pk':
    case 'p2sh-p2pkh':
      if (prevOutType && prevOutType !== 'scripthash') {
        throw new TypeError(
          `input #${signParams.vin} is not of type ${posType}: ${prevOutType}`,
        );
      }
      tfMessage(
        typeforce.Buffer,
        signParams.redeemScript,
        `${posType} requires redeemScript`,
      );
      break;
    case 'cp2pkh':
      if (prevOutType && prevOutType !== 'coloredpubkeyhash') {
        throw new TypeError(
          `input #${signParams.vin} is not of type cp2pkh: ${prevOutType}`,
        );
      }
      tfMessage(
        typeforce.value(undefined),
        signParams.redeemScript,
        `${posType} requires NO redeemScript`,
      );
      break;
    case 'cp2sh':
      if (prevOutType && prevOutType !== 'coloredscripthash') {
        throw new TypeError(
          `input #${signParams.vin} is not of type cp2sh: ${prevOutType}`,
        );
      }
      tfMessage(
        typeforce.Buffer,
        signParams.redeemScript,
        `${posType} requires redeemScript`,
      );
      break;
  }
}
function trySign({
  input,
  ourPubKey,
  keyPair,
  signatureHash,
  hashType,
  useLowR,
}) {
  // enforce in order signing of public keys
  let signed = false;
  for (const [i, pubKey] of input.pubkeys.entries()) {
    if (!ourPubKey.equals(pubKey)) continue;
    if (input.signatures[i]) throw new Error('Signature already exists');
    const signature = keyPair.sign(signatureHash, useLowR);
    input.signatures[i] = bscript.signature.encode(signature, hashType);
    signed = true;
  }
  if (!signed) throw new Error('Key pair cannot sign for this input');
}
function getSigningData(
  network,
  inputs,
  needsOutputs,
  tx,
  signParams,
  keyPair,
  redeemScript,
  hashType,
  useLowR,
) {
  let vin;
  if (typeof signParams === 'number') {
    console.warn(
      'DEPRECATED: TransactionBuilder sign method arguments ' +
        'will change in v6, please use the TxbSignArg interface',
    );
    vin = signParams;
  } else if (typeof signParams === 'object') {
    checkSignArgs(inputs, signParams);
    ({ vin, keyPair, redeemScript, hashType } = signParams);
  } else {
    throw new TypeError(
      'TransactionBuilder sign first arg must be TxbSignArg or number',
    );
  }
  if (keyPair === undefined) {
    throw new Error('sign requires keypair');
  }
  // TODO: remove keyPair.network matching in 4.0.0
  if (keyPair.network && keyPair.network !== network)
    throw new TypeError('Inconsistent network');
  if (!inputs[vin]) throw new Error('No input at index: ' + vin);
  hashType = hashType || transaction_1.Transaction.SIGHASH_ALL;
  if (needsOutputs(hashType)) throw new Error('Transaction needs outputs');
  const input = inputs[vin];
  // if redeemScript was previously provided, enforce consistency
  if (
    input.redeemScript !== undefined &&
    redeemScript &&
    !input.redeemScript.equals(redeemScript)
  ) {
    throw new Error('Inconsistent redeemScript');
  }
  const ourPubKey =
    keyPair.publicKey || (keyPair.getPublicKey && keyPair.getPublicKey());
  if (!canSign(input)) {
    const prepared = prepareInput(
      input,
      ourPubKey,
      redeemScript,
      typeof signParams === 'object' ? signParams.prevOutScriptType : undefined,
    );
    // updates inline
    Object.assign(input, prepared);
    if (!canSign(input)) throw Error(input.prevOutType + ' not supported');
  }
  // ready to sign
  const signatureHash = tx.hashForSignature(vin, input.signScript, hashType);
  return {
    input,
    ourPubKey,
    keyPair,
    signatureHash,
    hashType,
    useLowR: !!useLowR,
  };
}
