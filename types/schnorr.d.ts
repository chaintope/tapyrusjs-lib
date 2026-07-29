/**
 * Sign a 32-byte hash. Returns the 64-byte signature Rx || s.
 * The 1-byte sighash flag is not appended; the caller adds it where the
 * script or the PSTT format requires it.
 */
export declare function sign(privateKey: Buffer, hash: Buffer): Buffer;
/**
 * Verify a 64-byte signature (Rx || s) against a 32-byte hash by computing
 * R' = sG - eP and checking that R'.y is a quadratic residue and R'.x == Rx.
 */
export declare function verify(publicKey: Buffer, hash: Buffer, signature: Buffer): boolean;
