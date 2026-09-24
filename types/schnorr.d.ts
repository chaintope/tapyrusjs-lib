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
export declare function sign(privateKey: Buffer, hash: Buffer): Buffer;
/**
 * Verify a 64-byte signature (Rx || s) against a 32-byte hash by computing
 * R' = sG - eP and checking that R'.y is a quadratic residue and R'.x == Rx.
 *
 * Accepts a 33-byte compressed or a 65-byte uncompressed public key, and no
 * other encoding. The point is parsed by libsecp256k1, which rejects a pair
 * that is not on the curve.
 */
export declare function verify(publicKey: Buffer, hash: Buffer, signature: Buffer): boolean;
