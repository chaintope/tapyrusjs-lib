'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.fromBase58Check = fromBase58Check;
exports.toBase58Check = toBase58Check;
exports.fromOutputScript = fromOutputScript;
exports.toOutputScript = toOutputScript;
const networks = require('./networks');
const payments = require('./payments');
const bscript = require('./script');
const types = require('./types');
const bs58check = require('bs58check');
const typeforce = require('typeforce');
const PUBKEY_HASH_LENGTH = 20;
const COLOR_ID_LENGTH = 33;
const UNCOLORED_LENGTH = 1 + PUBKEY_HASH_LENGTH; // 21
const COLORED_LENGTH = 1 + PUBKEY_HASH_LENGTH + COLOR_ID_LENGTH; // 54
function fromBase58Check(address) {
  const payload = bs58check.decode(address);
  // TODO: 4.0.0, move to "toOutputScript"
  if (payload.length < UNCOLORED_LENGTH)
    throw new TypeError(`${address} is too short(${payload.length})`);
  if (payload.length > COLORED_LENGTH)
    throw new TypeError(`${address} is too long(${payload.length})`);
  const version = payload.readUInt8(0);
  if (payload.length > UNCOLORED_LENGTH) {
    // Colored
    const colorId = payload.slice(1, 1 + COLOR_ID_LENGTH);
    const hash = payload.slice(1 + COLOR_ID_LENGTH);
    if (hash.length !== PUBKEY_HASH_LENGTH) {
      throw new TypeError(`Invalid hash(${hash.toString('hex')})`);
    }
    if (!types.ColorId(colorId)) {
      throw new TypeError(`${address} has an invalid color identifier`);
    }
    return { version, colorId, hash };
  } else {
    // Uncolored
    const hash = payload.slice(1);
    return { version, hash };
  }
}
function toBase58Check(hash, version, colorId) {
  typeforce(
    types.tuple(types.Hash160bit, types.UInt8, types.maybe(types.ColorId)),
    arguments,
  );
  const payload = colorId
    ? Buffer.alloc(COLORED_LENGTH)
    : Buffer.alloc(UNCOLORED_LENGTH);
  payload.writeUInt8(version, 0);
  if (colorId) {
    colorId.copy(payload, 1);
    hash.copy(payload, 1 + COLOR_ID_LENGTH);
  } else {
    hash.copy(payload, 1);
  }
  return bs58check.encode(payload);
}
function fromOutputScript(output, network) {
  try {
    const payment = payments.util.fromOutputScript(output, network);
    return payment.address;
  } catch (e) {}
  throw new Error(bscript.toASM(output) + ' has no matching Address');
}
function requireOutput(payment, address) {
  if (!payment.output) throw new Error(address + ' has no matching Script');
  return payment.output;
}
function toOutputScript(address, network) {
  network = network || networks.prod;
  let decodeBase58;
  try {
    decodeBase58 = fromBase58Check(address);
  } catch (e) {}
  if (decodeBase58) {
    const { version, hash, colorId } = decodeBase58;
    const colored =
      version === network.coloredPubKeyHash ||
      version === network.coloredScriptHash;
    // the version byte and the payload must agree on whether there is a colour
    if (colored && !colorId)
      throw new Error(address + ' is missing a color identifier');
    if (!colored && colorId)
      throw new Error(address + ' has an unexpected color identifier');
    if (version === network.pubKeyHash)
      return requireOutput(payments.p2pkh({ hash }), address);
    if (version === network.scriptHash)
      return requireOutput(payments.p2sh({ hash }), address);
    if (version === network.coloredPubKeyHash)
      return requireOutput(payments.cp2pkh({ hash, colorId }), address);
    if (version === network.coloredScriptHash)
      return requireOutput(payments.cp2sh({ hash, colorId }), address);
  }
  throw new Error(address + ' has no matching Script');
}
