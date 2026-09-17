// Schnorr signature scheme used by the Tapyrus script interpreter.
//
// This is NOT BIP340. It follows the implementation tapyrus-core actually signs
// with, secp256k1_schnorr_sign of the bundled libsecp256k1 fork
// (chaintope/secp256k1, src/modules/schnorr/main_impl.h):
//
//   - the nonce is derived with RFC 6979 (HMAC-DRBG over SHA256) over
//     key32 || msg32 || algo16, with algo16 = "SCHNORR + SHA256" (exactly 16
//     ASCII bytes),
//   - the sign of the nonce is flipped so that the y coordinate of R is a
//     quadratic residue modulo p (Jacobi symbol 1),
//   - the challenge is e = SHA256(Rx(32) || compressed pubkey(33) || msg(32)) mod n,
//   - the signature is Rx(32) || s(32), 64 bytes in total.
//
// See https://github.com/chaintope/tapyrus-core/blob/master/doc/tapyrus/schnorr_signature.md

import * as bcrypto from './crypto';
import * as types from './types';

const createHmac = require('create-hmac');
const ecc = require('tiny-secp256k1');
const typeforce = require('typeforce');

const ZERO = BigInt(0);
const ONE = BigInt(1);
const TWO = BigInt(2);
const EIGHT = BigInt(8);

const P = BigInt(
  '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
);
const N = BigInt(
  '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
);

// "SCHNORR + SHA256" is exactly 16 ASCII bytes, so no padding is needed.
const ALGO16 = Buffer.from('SCHNORR + SHA256', 'ascii');

function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r < ZERO ? r + m : r;
}

function powmod(base: bigint, exponent: bigint, m: bigint): bigint {
  let result = ONE;
  let b = mod(base, m);
  let e = exponent;
  while (e > ZERO) {
    if (e & ONE) result = (result * b) % m;
    b = (b * b) % m;
    e >>= ONE;
  }
  return result;
}

// Builds the integer byte by byte rather than through a hex string, so that no
// copy of a secret ends up in a string, which can not be wiped.
function bufferToBigInt(buffer: Buffer): bigint {
  let result = ZERO;
  for (const byte of buffer) result = (result << EIGHT) | BigInt(byte);
  return result;
}

function bigIntToBuffer32(value: bigint): Buffer {
  return Buffer.from(value.toString(16).padStart(64, '0'), 'hex');
}

function isQuadraticResidue(y: bigint): boolean {
  return powmod(y, (P - ONE) / TWO, P) === ONE;
}

/** The x coordinate of an uncompressed point, as returned by tiny-secp256k1. */
function pointX(point: Uint8Array): Buffer {
  return Buffer.from(point.slice(1, 33));
}

/** The y coordinate of an uncompressed point. */
function pointY(point: Uint8Array): bigint {
  return bufferToBigInt(Buffer.from(point.slice(33)));
}

// libsecp256k1's nonce_function_rfc6979 with keydata = key32 || msg32 || algo16.
// Returns the nonce as 32 bytes, so that it can be handed to the constant time
// scalar operations without passing through a bigint.
function rfc6979Nonce(privateKey: Buffer, hash: Buffer): Buffer {
  const keydata = Buffer.concat([privateKey, hash, ALGO16]);
  let v = Buffer.alloc(32, 0x01);
  let k = Buffer.alloc(32, 0x00);

  try {
    k = createHmac('sha256', k)
      .update(Buffer.concat([v, Buffer.from([0x00]), keydata]))
      .digest();
    v = createHmac('sha256', k)
      .update(v)
      .digest();
    k = createHmac('sha256', k)
      .update(Buffer.concat([v, Buffer.from([0x01]), keydata]))
      .digest();
    v = createHmac('sha256', k)
      .update(v)
      .digest();
  } finally {
    // keydata holds a copy of the private key
    keydata.fill(0);
  }

  for (;;) {
    v = createHmac('sha256', k)
      .update(v)
      .digest();
    // isPrivate is the same 0 < v < n test, without building a bigint
    if (ecc.isPrivate(v)) return v;
    k = createHmac('sha256', k)
      .update(Buffer.concat([v, Buffer.from([0x00])]))
      .digest();
    v = createHmac('sha256', k)
      .update(v)
      .digest();
  }
}

function challenge(rx: Buffer, compressedPubkey: Buffer, hash: Buffer): bigint {
  return mod(
    bufferToBigInt(bcrypto.sha256(Buffer.concat([rx, compressedPubkey, hash]))),
    N,
  );
}

/**
 * Sign a 32-byte hash. Returns the 64-byte signature Rx || s.
 * The 1-byte sighash flag is not appended; the caller adds it where the
 * script or the PSTT format requires it.
 *
 * Every operation on the private key or on the nonce is delegated to
 * tiny-secp256k1, which wraps libsecp256k1 and runs in constant time. The one
 * exception is the product e*d, which has no constant time equivalent in that
 * library; it is a single modular multiplication rather than a bit by bit
 * scalar multiplication.
 */
export function sign(privateKey: Buffer, hash: Buffer): Buffer {
  typeforce(types.tuple(types.BufferN(32), types.Hash256bit), arguments);

  if (!ecc.isPrivate(privateKey)) throw new Error('Invalid private key');

  const compressedPubkey = Buffer.from(ecc.pointFromScalar(privateKey, true));

  let k = rfc6979Nonce(privateKey, hash);
  const r = ecc.pointFromScalar(k, false);
  if (r === null) throw new Error('Invalid nonce');

  const rx = pointX(r);
  // flip the nonce so that R.y is a quadratic residue
  if (!isQuadraticResidue(pointY(r))) k = Buffer.from(ecc.privateNegate(k));

  const e = challenge(rx, compressedPubkey, hash);
  const ed = bigIntToBuffer32(mod(e * bufferToBigInt(privateKey), N));

  const s = ecc.privateAdd(k, ed);
  if (s === null) throw new Error('Invalid signature');

  return Buffer.concat([rx, Buffer.from(s)]);
}

/**
 * Verify a 64-byte signature (Rx || s) against a 32-byte hash by computing
 * R' = sG - eP and checking that R'.y is a quadratic residue and R'.x == Rx.
 *
 * Accepts a 33-byte compressed or a 65-byte uncompressed public key. The point
 * is parsed by libsecp256k1, which rejects a pair that is not on the curve.
 */
export function verify(
  publicKey: Buffer,
  hash: Buffer,
  signature: Buffer,
): boolean {
  typeforce(
    types.tuple(types.Buffer, types.Hash256bit, types.Buffer),
    arguments,
  );

  if (signature.length !== 64) return false;

  const rx = signature.subarray(0, 32);
  const r = bufferToBigInt(rx);
  const s = bufferToBigInt(signature.subarray(32));
  if (r >= P || s >= N) return false;

  if (!ecc.isPoint(publicKey)) return false;
  const compressedPubkey = Buffer.from(ecc.pointCompress(publicKey, true));

  const e = challenge(rx, compressedPubkey, hash);
  const negE = mod(N - e, N);

  // a zero scalar would multiply to the point at infinity, which
  // tiny-secp256k1 does not accept as a tweak
  const sG =
    s === ZERO ? null : ecc.pointFromScalar(bigIntToBuffer32(s), false);
  const eP =
    negE === ZERO
      ? null
      : ecc.pointMultiply(publicKey, bigIntToBuffer32(negE), false);

  let computed: Uint8Array | null;
  if (sG === null) computed = eP;
  else if (eP === null) computed = sG;
  else computed = ecc.pointAdd(sG, eP, false);
  if (computed === null) return false;

  return (
    isQuadraticResidue(pointY(computed)) &&
    bufferToBigInt(pointX(computed)) === r
  );
}
