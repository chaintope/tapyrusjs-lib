'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.fromOutputScript = fromOutputScript;
exports.addressFn = addressFn;
exports.coloredAddressFn = coloredAddressFn;
exports.chunksFn = chunksFn;
exports.redeemFn = redeemFn;
exports.checkHash = checkHash;
exports.validColorId = validColorId;
exports.stacksEqual = stacksEqual;
exports.checkInput = checkInput;
exports.checkRedeem = checkRedeem;
const bcrypto = require('../crypto');
const networks = require('../networks');
const payments = require('../payments');
const bscript = require('../script');
const lazy = require('./lazy');
const bs58check = require('bs58check');
function fromOutputScript(output, network) {
  network = network || networks.prod;
  try {
    return payments.p2pkh({ output, network });
  } catch (e) {}
  try {
    return payments.p2sh({ output, network });
  } catch (e) {}
  try {
    return payments.cp2pkh({ output, network });
  } catch (e) {}
  try {
    return payments.cp2sh({ output, network });
  } catch (e) {}
  throw new Error(bscript.toASM(output) + ' is not standard script');
}
function addressFn(address) {
  return lazy.value(() => {
    const payload = bs58check.decode(address);
    const version = payload.readUInt8(0);
    const hash = payload.slice(1);
    return { version, hash };
  });
}
function coloredAddressFn(address) {
  return lazy.value(() => {
    const payload = bs58check.decode(address);
    const version = payload.readUInt8(0);
    const colorId = payload.slice(1, 34);
    const hash = payload.slice(34);
    return { version, colorId, hash };
  });
}
function chunksFn(script) {
  return lazy.value(() => {
    return bscript.decompile(script);
  });
}
function redeemFn(a, network) {
  return lazy.value(() => {
    const chunks = chunksFn(a.input)();
    return {
      network,
      output: chunks[chunks.length - 1],
      input: bscript.compile(chunks.slice(0, -1)),
    };
  });
}
function checkHash(hash, hash2) {
  if (hash.length > 0 && !hash.equals(hash2))
    throw new TypeError('Hash mismatch');
}
function validColorId(colorId, newColorId) {
  if (colorId.length > 0 && !colorId.equals(newColorId))
    throw new TypeError('ColorId mismatch');
  return newColorId;
}
function stacksEqual(a, b) {
  if (a.length !== b.length) return false;
  return a.every((x, i) => {
    return x.equals(b[i]);
  });
}
function checkInput(_chunksFn, _redeemFn, hashForCheck) {
  const chunks = _chunksFn();
  if (!chunks || chunks.length < 1) throw new TypeError('Input too short');
  const redeem = _redeemFn();
  if (!Buffer.isBuffer(redeem.output)) throw new TypeError('Input is invalid');
  return _checkRedeem(redeem, hashForCheck);
}
function checkRedeem(a, network, _redeemFn, hashForCheck) {
  if (a.redeem) {
    if (a.redeem.network && a.redeem.network !== network)
      throw new TypeError('Network mismatch');
    if (a.input) {
      const redeem = _redeemFn();
      if (a.redeem.output && !a.redeem.output.equals(redeem.output))
        throw new TypeError('Redeem.output mismatch');
      if (a.redeem.input && !a.redeem.input.equals(redeem.input))
        throw new TypeError('Redeem.input mismatch');
    }
    _checkRedeem(a.redeem, hashForCheck);
  }
}
// inlined to prevent 'no-inner-declarations' failing
function _checkRedeem(redeem, hashForCheck) {
  let hash2 = null;
  // is the redeem output empty/invalid?
  if (redeem.output) {
    const decompile = bscript.decompile(redeem.output);
    if (!decompile || decompile.length < 1)
      throw new TypeError('Redeem.output too short');
    // match hash against other sources
    hash2 = bcrypto.hash160(redeem.output);
    checkHash(hashForCheck, hash2);
  }
  if (redeem.input) {
    if (redeem.input.length === 0) throw new TypeError('Empty input');
    const richunks = bscript.decompile(redeem.input);
    if (!bscript.isPushOnly(richunks))
      throw new TypeError('Non push-only scriptSig');
  }
  return hash2;
}
