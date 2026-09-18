import { Network } from './networks';
import * as networks from './networks';
import * as payments from './payments';
import * as bscript from './script';
import * as types from './types';

const bs58check = require('bs58check');
const typeforce = require('typeforce');

export interface Base58CheckResult {
  hash: Buffer;
  version: number;
  colorId?: Buffer;
}

const PUBKEY_HASH_LENGTH = 20;
const COLOR_ID_LENGTH = 33;
const UNCOLORED_LENGTH = 1 + PUBKEY_HASH_LENGTH; // 21
const COLORED_LENGTH = 1 + PUBKEY_HASH_LENGTH + COLOR_ID_LENGTH; // 54

export function fromBase58Check(address: string): Base58CheckResult {
  const payload: Buffer = bs58check.decode(address);

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
      throw new TypeError(`Invalid hash(${hash})`);
    }
    return { version, colorId, hash };
  } else {
    // Uncolored
    const hash = payload.slice(1);
    return { version, hash };
  }
}

export function toBase58Check(
  hash: Buffer,
  version: number,
  colorId?: Buffer,
): string {
  typeforce(types.tuple(types.Hash160bit, types.UInt8), arguments);

  const payload = colorId
    ? Buffer.allocUnsafe(COLORED_LENGTH)
    : Buffer.allocUnsafe(UNCOLORED_LENGTH);
  payload.writeUInt8(version, 0);
  if (colorId) {
    colorId.copy(payload, 1);
    hash.copy(payload, 1 + COLOR_ID_LENGTH);
  } else {
    hash.copy(payload, 1);
  }

  return bs58check.encode(payload);
}

export function fromOutputScript(output: Buffer, network?: Network): string {
  try {
    const payment = payments.util.fromOutputScript(output, network);
    return payment.address!;
  } catch (e) {}
  throw new Error(bscript.toASM(output) + ' has no matching Address');
}

export function toOutputScript(address: string, network?: Network): Buffer {
  network = network || networks.prod;

  let decodeBase58: Base58CheckResult | undefined;
  try {
    decodeBase58 = fromBase58Check(address);
  } catch (e) {}

  if (decodeBase58) {
    if (decodeBase58.version === network.pubKeyHash)
      return payments.p2pkh({ hash: decodeBase58.hash }).output as Buffer;
    if (decodeBase58.version === network.scriptHash)
      return payments.p2sh({ hash: decodeBase58.hash }).output as Buffer;
    if (decodeBase58.version === network.coloredPubKeyHash)
      return payments.cp2pkh({
        hash: decodeBase58.hash,
        colorId: decodeBase58.colorId,
      }).output as Buffer;
    if (decodeBase58.version === network.coloredScriptHash)
      return payments.cp2sh({
        hash: decodeBase58.hash,
        colorId: decodeBase58.colorId,
      }).output as Buffer;
  }

  throw new Error(address + ' has no matching Script');
}
