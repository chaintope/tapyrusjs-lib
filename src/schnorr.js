'use strict';
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
Object.defineProperty(exports, '__esModule', { value: true });
exports.sign = sign;
exports.verify = verify;
const bcrypto = require('./crypto');
const types = require('./types');
const createHmac = require('create-hmac');
const typeforce = require('typeforce');
const ZERO = BigInt(0);
const ONE = BigInt(1);
const TWO = BigInt(2);
const THREE = BigInt(3);
const SEVEN = BigInt(7);
const FOUR = BigInt(4);
const P = BigInt(
  '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
);
const N = BigInt(
  '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
);
const GX = BigInt(
  '0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
);
const GY = BigInt(
  '0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
);
// "SCHNORR + SHA256" is exactly 16 ASCII bytes, so no padding is needed.
const ALGO16 = Buffer.from('SCHNORR + SHA256', 'ascii');
const G = { x: GX, y: GY };
function mod(a, m) {
  const r = a % m;
  return r < ZERO ? r + m : r;
}
function powmod(base, exponent, m) {
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
// p is prime, so a^(p-2) is the modular inverse of a.
function inv(a, m) {
  return powmod(a, m - TWO, m);
}
function pointAdd(a, b) {
  if (a === null) return b;
  if (b === null) return a;
  if (a.x === b.x && mod(a.y + b.y, P) === ZERO) return null;
  let lam;
  if (a.x === b.x && a.y === b.y) {
    lam = mod(THREE * a.x * a.x * inv(TWO * a.y, P), P);
  } else {
    lam = mod((b.y - a.y) * inv(mod(b.x - a.x, P), P), P);
  }
  const x = mod(lam * lam - a.x - b.x, P);
  return { x, y: mod(lam * (a.x - x) - a.y, P) };
}
function pointMul(k, point) {
  let result = null;
  let addend = point;
  let e = k;
  while (e > ZERO) {
    if (e & ONE) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    e >>= ONE;
  }
  return result;
}
function bufferToBigInt(buffer) {
  return BigInt('0x' + (buffer.toString('hex') || '0'));
}
function bigIntToBuffer32(value) {
  return Buffer.from(value.toString(16).padStart(64, '0'), 'hex');
}
function isQuadraticResidue(y) {
  return powmod(y, (P - ONE) / TWO, P) === ONE;
}
function compress(point) {
  return Buffer.concat([
    Buffer.from([point.y & ONE ? 0x03 : 0x02]),
    bigIntToBuffer32(point.x),
  ]);
}
function isOnCurve(x, y) {
  return mod(y * y, P) === mod(powmod(x, THREE, P) + SEVEN, P);
}
// Accepts a 33-byte compressed or a 65-byte uncompressed public key.
function decodePoint(publicKey) {
  if (publicKey.length === 65) {
    if (publicKey[0] !== 0x04) throw new Error('Invalid public key prefix');
    const px = bufferToBigInt(publicKey.subarray(1, 33));
    const py = bufferToBigInt(publicKey.subarray(33, 65));
    // An uncompressed key states both coordinates, so unlike the compressed
    // form nothing forces the pair onto the curve. A point of another curve
    // takes the group law used here outside secp256k1, where a signature can
    // be forged: (0, 0) doubles to the point at infinity, which cancels the
    // public key out of the verification equation altogether.
    if (px >= P || py >= P || !isOnCurve(px, py))
      throw new Error('Invalid public key');
    return { x: px, y: py };
  }
  if (
    publicKey.length !== 33 ||
    (publicKey[0] !== 0x02 && publicKey[0] !== 0x03)
  )
    throw new Error('Invalid public key');
  const x = bufferToBigInt(publicKey.subarray(1));
  if (x >= P) throw new Error('Invalid public key');
  const ySquare = mod(powmod(x, THREE, P) + SEVEN, P);
  let y = powmod(ySquare, (P + ONE) / FOUR, P);
  if (mod(y * y, P) !== ySquare) throw new Error('Invalid public key');
  if ((y & ONE) !== BigInt(publicKey[0] & 1)) y = P - y;
  return { x, y };
}
// libsecp256k1's nonce_function_rfc6979 with keydata = key32 || msg32 || algo16.
function rfc6979Nonce(privateKey, hash) {
  const keydata = Buffer.concat([privateKey, hash, ALGO16]);
  let v = Buffer.alloc(32, 0x01);
  let k = Buffer.alloc(32, 0x00);
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
  for (;;) {
    v = createHmac('sha256', k)
      .update(v)
      .digest();
    const candidate = bufferToBigInt(v);
    if (candidate > ZERO && candidate < N) return candidate;
    k = createHmac('sha256', k)
      .update(Buffer.concat([v, Buffer.from([0x00])]))
      .digest();
    v = createHmac('sha256', k)
      .update(v)
      .digest();
  }
}
function challenge(rx, compressedPubkey, hash) {
  return mod(
    bufferToBigInt(bcrypto.sha256(Buffer.concat([rx, compressedPubkey, hash]))),
    N,
  );
}
/**
 * Sign a 32-byte hash. Returns the 64-byte signature Rx || s.
 * The 1-byte sighash flag is not appended; the caller adds it where the
 * script or the PSTT format requires it.
 */
function sign(privateKey, hash) {
  typeforce(types.tuple(types.BufferN(32), types.Hash256bit), arguments);
  const d = bufferToBigInt(privateKey);
  if (d <= ZERO || d >= N) throw new Error('Invalid private key');
  const publicKey = pointMul(d, G);
  if (publicKey === null) throw new Error('Invalid private key');
  let k = rfc6979Nonce(privateKey, hash);
  const r = pointMul(k, G);
  if (r === null) throw new Error('Invalid nonce');
  if (!isQuadraticResidue(r.y)) k = N - k;
  const rx = bigIntToBuffer32(r.x);
  const e = challenge(rx, compress(publicKey), hash);
  return Buffer.concat([rx, bigIntToBuffer32(mod(k + e * d, N))]);
}
/**
 * Verify a 64-byte signature (Rx || s) against a 32-byte hash by computing
 * R' = sG - eP and checking that R'.y is a quadratic residue and R'.x == Rx.
 */
function verify(publicKey, hash, signature) {
  typeforce(
    types.tuple(types.Buffer, types.Hash256bit, types.Buffer),
    arguments,
  );
  if (signature.length !== 64) return false;
  const r = bufferToBigInt(signature.subarray(0, 32));
  const s = bufferToBigInt(signature.subarray(32));
  if (r >= P || s >= N) return false;
  let point;
  try {
    point = decodePoint(publicKey);
  } catch (e) {
    return false;
  }
  const e = challenge(signature.subarray(0, 32), compress(point), hash);
  const computed = pointAdd(pointMul(s, G), pointMul(mod(N - e, N), point));
  if (computed === null) return false;
  return isQuadraticResidue(computed.y) && computed.x === r;
}
