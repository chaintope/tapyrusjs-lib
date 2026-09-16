import * as baddress from './address';
import { reverseBuffer } from './bufferutils';
import * as classify from './classify';
import * as bcrypto from './crypto';
import { Signer } from './ecpair';
import * as ECPair from './ecpair';
import { Network } from './networks';
import * as networks from './networks';
import { Payment } from './payments';
import * as payments from './payments';
import * as bscript from './script';
import { OPS as ops } from './script';
import { Output, Transaction } from './transaction';
import * as types from './types';
const typeforce = require('typeforce');

const SCRIPT_TYPES = classify.types;

const PREVOUT_TYPES: Set<string> = new Set([
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

type MaybeBuffer = Buffer | undefined;
type TxbSignatures = Buffer[] | MaybeBuffer[];
type TxbPubkeys = MaybeBuffer[];
type TxbScriptType = string;
type TxbScript = Buffer;

interface TxbInput {
  value?: number;
  signScript?: TxbScript;
  signType?: TxbScriptType;
  prevOutScript?: TxbScript;
  redeemScript?: TxbScript;
  redeemScriptType?: TxbScriptType;
  prevOutType?: TxbScriptType;
  pubkeys?: TxbPubkeys;
  signatures?: TxbSignatures;
  script?: TxbScript;
  sequence?: number;
  scriptSig?: TxbScript;
  maxSignatures?: number;
}

interface TxbOutput {
  type: string;
  pubkeys?: TxbPubkeys;
  signatures?: TxbSignatures;
  maxSignatures?: number;
}

interface TxbSignArg {
  prevOutScriptType: string;
  vin: number;
  keyPair: Signer;
  redeemScript?: Buffer;
  hashType?: number;
}

function tfMessage(type: any, value: any, message: string): void {
  try {
    typeforce(type, value);
  } catch (err) {
    throw new Error(message);
  }
}

function txIsString(tx: Buffer | string | Transaction): tx is string {
  return typeof tx === 'string' || tx instanceof String;
}

function txIsTransaction(tx: Buffer | string | Transaction): tx is Transaction {
  return tx instanceof Transaction;
}

export class TransactionBuilder {
  static fromTransaction(
    transaction: Transaction,
    network?: Network,
  ): TransactionBuilder {
    const txb = new TransactionBuilder(network);

    // Copy transaction fields
    txb.setVersion(transaction.version);
    txb.setLockTime(transaction.locktime);

    // Copy outputs (done first to avoid signature invalidation)
    transaction.outs.forEach(txOut => {
      txb.addOutput(txOut.script, (txOut as Output).value);
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

  private __PREV_TX_SET: { [index: string]: boolean };
  private __INPUTS: TxbInput[];
  private __TX: Transaction;
  private __USE_LOW_R: boolean;

  // WARNING: maximumFeeRate is __NOT__ to be relied on,
  //          it's just another potential safety mechanism (safety in-depth)
  constructor(
    public network: Network = networks.prod,
    public maximumFeeRate: number = 2500,
  ) {
    this.__PREV_TX_SET = {};
    this.__INPUTS = [];
    this.__TX = new Transaction();
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

  setLowR(setting?: boolean): boolean {
    typeforce(typeforce.maybe(typeforce.Boolean), setting);
    if (setting === undefined) {
      setting = true;
    }
    this.__USE_LOW_R = setting;
    return setting;
  }

  setLockTime(locktime: number): void {
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

  setVersion(version: number): void {
    typeforce(types.UInt32, version);

    // XXX: this might eventually become more complex depending on what the versions represent
    this.__TX.version = version;
  }

  addInput(
    txHash: Buffer | string | Transaction,
    vout: number,
    sequence?: number,
    prevOutScript?: Buffer,
  ): number {
    if (!this.__canModifyInputs()) {
      throw new Error('No, this would invalidate signatures');
    }

    let value: number | undefined;

    // is it a hex string?
    if (txIsString(txHash)) {
      // transaction hashs's are displayed in reverse order, un-reverse it
      txHash = reverseBuffer(Buffer.from(txHash, 'hex'));

      // is it a Transaction object?
    } else if (txIsTransaction(txHash)) {
      const txOut = txHash.outs[vout];
      prevOutScript = txOut.script;
      value = (txOut as Output).value;

      txHash = txHash.getHash() as Buffer;
    }

    return this.__addInputUnsafe(txHash, vout, {
      sequence,
      prevOutScript,
      value,
    });
  }

  addOutput(scriptPubKey: string | Buffer, value: number): number {
    if (!this.__canModifyOutputs()) {
      throw new Error('No, this would invalidate signatures');
    }

    // Attempt to get a script if it's a base58 address string
    if (typeof scriptPubKey === 'string') {
      scriptPubKey = baddress.toOutputScript(scriptPubKey, this.network);
    }

    return this.__TX.addOutput(scriptPubKey, value);
  }

  build(): Transaction {
    return this.__build(false);
  }

  buildIncomplete(): Transaction {
    return this.__build(true);
  }

  sign(
    signParams: number | TxbSignArg,
    keyPair?: Signer,
    redeemScript?: Buffer,
    hashType?: number,
  ): void {
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

  private __addInputUnsafe(
    txHash: Buffer,
    vout: number,
    options: TxbInput,
  ): number {
    if (Transaction.isCoinbaseHash(txHash)) {
      throw new Error('coinbase inputs not supported');
    }

    const prevTxOut = txHash.toString('hex') + ':' + vout;
    if (this.__PREV_TX_SET[prevTxOut] !== undefined)
      throw new Error('Duplicate TxOut: ' + prevTxOut);

    let input: TxbInput = {};

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

  private __build(allowIncomplete?: boolean): Transaction {
    if (!allowIncomplete) {
      if (!this.__TX.ins.length) throw new Error('Transaction has no inputs');
      if (!this.__TX.outs.length) throw new Error('Transaction has no outputs');
    }

    const tx = this.__TX.clone();

    // create script signatures from inputs
    this.__INPUTS.forEach((input, i) => {
      if (!input.prevOutType && !allowIncomplete)
        throw new Error('Transaction is not complete');

      const result = build(input.prevOutType!, input, allowIncomplete);
      if (!result) {
        if (!allowIncomplete && input.prevOutType === SCRIPT_TYPES.NONSTANDARD)
          throw new Error('Unknown input type');
        if (!allowIncomplete) throw new Error('Not enough information');
        return;
      }

      tx.setInputScript(i, result.input!);
    });

    if (!allowIncomplete) {
      // do not rely on this, its merely a last resort
      if (this.__overMaximumFees(tx.byteLength())) {
        throw new Error('Transaction has absurd fees');
      }
    }

    return tx;
  }

  private __canModifyInputs(): boolean {
    return this.__INPUTS.every(input => {
      if (!input.signatures) return true;

      return input.signatures.every(signature => {
        if (!signature) return true;
        const hashType = signatureHashType(signature);

        // if SIGHASH_ANYONECANPAY is set, signatures would not
        // be invalidated by more inputs
        return (hashType & Transaction.SIGHASH_ANYONECANPAY) !== 0;
      });
    });
  }

  private __needsOutputs(signingHashType: number): boolean {
    if (signingHashType === Transaction.SIGHASH_ALL) {
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
          if (hashType & Transaction.SIGHASH_NONE) return false; // SIGHASH_NONE doesn't care about outputs
          return true; // SIGHASH_* does care
        });
      })
    );
  }

  private __canModifyOutputs(): boolean {
    const nInputs = this.__TX.ins.length;
    const nOutputs = this.__TX.outs.length;

    return this.__INPUTS.every(input => {
      if (input.signatures === undefined) return true;

      return input.signatures.every(signature => {
        if (!signature) return true;
        const hashType = signatureHashType(signature);

        const hashTypeMod = hashType & 0x1f;
        if (hashTypeMod === Transaction.SIGHASH_NONE) return true;
        if (hashTypeMod === Transaction.SIGHASH_SINGLE) {
          // if SIGHASH_SINGLE is set, and nInputs > nOutputs
          // some signatures would be invalidated by the addition
          // of more outputs
          return nInputs <= nOutputs;
        }
        return false;
      });
    });
  }

  private __overMaximumFees(bytes: number): boolean {
    // not all inputs will have .value defined
    const incoming = this.__INPUTS.reduce((a, x) => a + (x.value! >>> 0), 0);

    // but all outputs do, and if we have any input value
    // we can immediately determine if the outputs are too small
    const outgoing = this.__TX.outs.reduce(
      (a, x) => a + (x as Output).value,
      0,
    );
    const fee = incoming - outgoing;
    const feeRate = fee / bytes;

    return feeRate > this.maximumFeeRate;
  }
}

function expandInput(
  scriptSig: Buffer,
  type?: string,
  scriptPubKey?: Buffer,
): TxbInput {
  if (scriptSig.length === 0) return {};
  if (!type) {
    const ssType: string | undefined = classify.input(scriptSig, true);
    if (ssType !== SCRIPT_TYPES.NONSTANDARD) type = ssType;
  }

  switch (type) {
    case SCRIPT_TYPES.P2PKH: {
      const { output, pubkey, signature } = payments.p2pkh({
        input: scriptSig,
      });

      return {
        prevOutScript: output,
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

    const outputType = classify.output(redeem!.output!);
    const expanded = expandInput(redeem!.input!, outputType, redeem!.output);
    if (!expanded.prevOutType) return {};

    return {
      prevOutScript: output,
      prevOutType: SCRIPT_TYPES.P2SH,
      redeemScript: redeem!.output,
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
function fixMultisigOrder(
  input: TxbInput,
  transaction: Transaction,
  vin: number,
): void {
  if (input.redeemScriptType !== SCRIPT_TYPES.P2MS || !input.redeemScript)
    return;
  if (input.pubkeys!.length === input.signatures!.length) return;

  const unmatched = input.signatures!.concat();

  input.signatures = input.pubkeys!.map(pubKey => {
    const keyPair = ECPair.fromPublicKey(pubKey!);
    let match: Buffer | undefined;

    // check for a signature
    unmatched.some((signature, i) => {
      // skip if undefined || OP_0
      if (!signature) return false;

      // TODO: avoid O(n) hashForSignature
      const parsed = bscript.signature.decode(signature);
      const hash = transaction.hashForSignature(
        vin,
        input.redeemScript!,
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

function expandOutput(script: Buffer, ourPubKey?: Buffer): TxbOutput {
  typeforce(types.Buffer, script);
  const type = classify.output(script);

  switch (type) {
    case SCRIPT_TYPES.P2PKH: {
      if (!ourPubKey) return { type };

      // does our hash160(pubKey) match the output scripts?
      const pkh1 = payments.p2pkh({ output: script }).hash;
      const pkh2 = bcrypto.hash160(ourPubKey);
      if (!pkh1!.equals(pkh2)) return { type };

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
        signatures: p2ms.pubkeys!.map((): undefined => undefined),
        maxSignatures: p2ms.m,
      };
    }

    case SCRIPT_TYPES.CP2PKH: {
      if (!ourPubKey) return { type };

      // does our hash160(pubKey) match the output scripts?
      const pkh1 = payments.cp2pkh({ output: script }).hash;
      const pkh2 = bcrypto.hash160(ourPubKey);
      if (!pkh1!.equals(pkh2)) return { type };

      return {
        type,
        pubkeys: [ourPubKey],
        signatures: [undefined],
      };
    }
  }

  return { type };
}

function prepareInput(
  input: TxbInput,
  ourPubKey: Buffer,
  redeemScript?: Buffer,
): TxbInput {
  if (redeemScript) {
    const p2sh = payments.p2sh({ redeem: { output: redeemScript } }) as Payment;

    if (input.prevOutScript) {
      let p2shAlt;
      try {
        p2shAlt = payments.p2sh({ output: input.prevOutScript }) as Payment;
      } catch (e) {
        throw new Error('PrevOutScript must be P2SH');
      }
      if (!p2sh.hash!.equals(p2shAlt.hash!))
        throw new Error('Redeem script inconsistent with prevOutScript');
    }

    const expanded = expandOutput(p2sh.redeem!.output!, ourPubKey);
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

      prevOutType: SCRIPT_TYPES.P2SH,
      prevOutScript: p2sh.output,

      signScript,
      signType: expanded.type,

      pubkeys: expanded.pubkeys,
      signatures: expanded.signatures,
      maxSignatures: expanded.maxSignatures,
    };
  }

  if (input.prevOutType && input.prevOutScript) {
    // embedded scripts are not possible without extra information
    if (input.prevOutType === SCRIPT_TYPES.P2SH)
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

function build(
  type: string,
  input: TxbInput,
  allowIncomplete?: boolean,
): Payment | undefined {
  const pubkeys = (input.pubkeys || []) as Buffer[];
  let signatures = (input.signatures || []) as Buffer[];

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
        signatures = signatures.map(x => x || ops.OP_0);
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
      const redeem = build(input.redeemScriptType!, input, allowIncomplete);
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
      const redeem = build(input.redeemScriptType!, input, allowIncomplete);
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

function canSign(input: TxbInput): boolean {
  return (
    input.signScript !== undefined &&
    input.signType !== undefined &&
    input.pubkeys !== undefined &&
    input.signatures !== undefined &&
    input.signatures.length === input.pubkeys.length &&
    input.pubkeys.length > 0
  );
}

function signatureHashType(buffer: Buffer): number {
  return buffer.readUInt8(buffer.length - 1);
}

function checkSignArgs(inputs: TxbInput[], signParams: TxbSignArg): void {
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
  const prevOutType = (inputs[signParams.vin] || []).prevOutType;
  const posType = signParams.prevOutScriptType;
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
      if (prevOutType && prevOutType !== 'coloredpubkeyhash') {
        throw new TypeError(
          `input #${signParams.vin} is not of type cp2pkh: ${prevOutType}`,
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
}: SigningData): void {
  // enforce in order signing of public keys
  let signed = false;
  for (const [i, pubKey] of input.pubkeys!.entries()) {
    if (!ourPubKey.equals(pubKey!)) continue;
    if (input.signatures![i]) throw new Error('Signature already exists');

    const signature = keyPair.sign(signatureHash, useLowR);
    input.signatures![i] = bscript.signature.encode(signature, hashType);
    signed = true;
  }

  if (!signed) throw new Error('Key pair cannot sign for this input');
}

interface SigningData {
  input: TxbInput;
  ourPubKey: Buffer;
  keyPair: Signer;
  signatureHash: Buffer;
  hashType: number;
  useLowR: boolean;
}

type HashTypeCheck = (hashType: number) => boolean;

function getSigningData(
  network: Network,
  inputs: TxbInput[],
  needsOutputs: HashTypeCheck,
  tx: Transaction,
  signParams: number | TxbSignArg,
  keyPair?: Signer,
  redeemScript?: Buffer,
  hashType?: number,
  useLowR?: boolean,
): SigningData {
  let vin: number;
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

  hashType = hashType || Transaction.SIGHASH_ALL;
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
    const prepared = prepareInput(input, ourPubKey, redeemScript);

    // updates inline
    Object.assign(input, prepared);

    if (!canSign(input)) throw Error(input.prevOutType + ' not supported');
  }

  // ready to sign
  const signatureHash: Buffer = tx.hashForSignature(
    vin,
    input.signScript as Buffer,
    hashType,
  );

  return {
    input,
    ourPubKey,
    keyPair,
    signatureHash,
    hashType,
    useLowR: !!useLowR,
  };
}
