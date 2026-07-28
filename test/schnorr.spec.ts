import * as assert from 'assert';
import { describe, it } from 'mocha';
import { crypto as bcrypto, ECPair, schnorr } from '..';

// Known-answer vectors from tapyrus-core's own C++ unit test,
// src/test/key_tests.cpp (`schnorr_signature` / deterministic signing), which
// exercises secp256k1_schnorr_sign of the bundled libsecp256k1 fork — the code
// path the node signs with.
//
// These must never be regenerated from this implementation, nor taken from
// another reimplementation of the scheme. Self-verification cannot detect a
// wrong nonce derivation, because verify() recomputes R' = sG - eP and never
// looks at how k was produced, so a KAT is the only thing pinning the nonce
// algorithm down — and only while it comes from the C code. An earlier revision
// sourced its KAT from a reimplementation, inherited that implementation's
// algo16 spelling along with it, and so compared two copies of one mistake: the
// test passed while this library produced signatures the node never would.
//
// The message is Hash("Very deterministic message"), i.e. SHA256d of the ASCII
// string, as in key_tests.cpp.
const KAT_HASH = Buffer.from(
  '5255683da567900bfd3e786ed8836a4e7763c221bf1ac20ece2a5171b9199e8a',
  'hex',
);

const KATS = [
  {
    // key_tests.cpp strSecret1 (5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj)
    privateKey: Buffer.from(
      '12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747',
      'hex',
    ),
    signature:
      '0567cbade8656cff3bb08d00913d59363273c32ea66130cf0c9b1be8e874b8bc' +
      'b0e62372c22e8ecd34ffeadda493beb221e52bf23413cc6c3abdcdfc03d0ed52',
  },
  {
    // key_tests.cpp strSecret2 (5KC4ejrDjv152FGwP386VD1i2NYc5KkfSMyv1nGy1VGDxGHqVY3)
    privateKey: Buffer.from(
      'b524c28b61c9b2c49b2c7dd4c2d75887abb78768c054bd7c01af4029f6c0d117',
      'hex',
    ),
    signature:
      '064623e23b59e1bd304156fb20c197eee23e6d10e021664aef3878364d9d5e17' +
      '5916f7909c9358192e9c1510ebb466b085e726aab0d71c6ef9f298b53ea179aa',
  },
];

const KAT = {
  privateKey: KATS[0].privateKey,
  hash: KAT_HASH,
  signature: KATS[0].signature,
};

describe('schnorr', () => {
  const keyPair = ECPair.fromPrivateKey(KAT.privateKey);

  describe('sign', () => {
    it('matches the tapyrus-core known-answer vectors', () => {
      for (const kat of KATS) {
        assert.strictEqual(
          schnorr.sign(kat.privateKey, KAT_HASH).toString('hex'),
          kat.signature,
        );
      }
    });

    it('derives the KAT message the way key_tests.cpp does', () => {
      // Hash("Very deterministic message") in tapyrus-core is SHA256d. Pinning
      // it here means the vectors above can be re-derived from key_tests.cpp
      // without trusting this file's hex.
      assert.strictEqual(
        bcrypto
          .hash256(Buffer.from('Very deterministic message', 'ascii'))
          .toString('hex'),
        KAT_HASH.toString('hex'),
      );
    });

    it('is deterministic', () => {
      assert.ok(
        schnorr
          .sign(KAT.privateKey, KAT.hash)
          .equals(schnorr.sign(KAT.privateKey, KAT.hash)),
      );
    });

    it('rejects an invalid private key', () => {
      assert.throws(
        () => schnorr.sign(Buffer.alloc(32, 0), KAT.hash),
        /Invalid private key/,
      );
      // Larger than the order of the curve.
      assert.throws(
        () => schnorr.sign(Buffer.alloc(32, 0xff), KAT.hash),
        /Invalid private key/,
      );
    });

    it('round-trips with keys of either y parity', () => {
      const evenY = Buffer.from(
        '0000000000000000000000000000000000000000000000000000000000000001',
        'hex',
      );
      const oddY = Buffer.from(
        '0000000000000000000000000000000000000000000000000000000000000002',
        'hex',
      );
      for (const privateKey of [evenY, oddY]) {
        const publicKey = ECPair.fromPrivateKey(privateKey).publicKey;
        const signature = schnorr.sign(privateKey, KAT.hash);
        assert.strictEqual(
          schnorr.verify(publicKey, KAT.hash, signature),
          true,
        );
      }
    });
  });

  describe('verify', () => {
    const signature = Buffer.from(KAT.signature, 'hex');

    it('accepts a compressed public key', () => {
      assert.strictEqual(
        schnorr.verify(keyPair.publicKey, KAT.hash, signature),
        true,
      );
    });

    it('accepts an uncompressed public key', () => {
      const uncompressed = ECPair.fromPrivateKey(KAT.privateKey, {
        compressed: false,
      }).publicKey;
      assert.strictEqual(
        schnorr.verify(uncompressed, KAT.hash, signature),
        true,
      );
    });

    it('rejects a tampered signature', () => {
      const tampered = Buffer.from(signature);
      tampered[63] ^= 0x01;
      assert.strictEqual(
        schnorr.verify(keyPair.publicKey, KAT.hash, tampered),
        false,
      );
    });

    it('rejects another message', () => {
      assert.strictEqual(
        schnorr.verify(keyPair.publicKey, Buffer.alloc(32, 0x11), signature),
        false,
      );
    });

    it('rejects another public key', () => {
      const other = ECPair.fromPrivateKey(Buffer.alloc(32, 0x42)).publicKey;
      assert.strictEqual(schnorr.verify(other, KAT.hash, signature), false);
    });

    it('rejects a signature that is not 64 bytes', () => {
      assert.strictEqual(
        schnorr.verify(keyPair.publicKey, KAT.hash, signature.slice(0, 63)),
        false,
      );
    });

    it('rejects a signature whose r or s is out of range', () => {
      const badR = Buffer.concat([Buffer.alloc(32, 0xff), signature.slice(32)]);
      const badS = Buffer.concat([
        signature.slice(0, 32),
        Buffer.alloc(32, 0xff),
      ]);
      assert.strictEqual(
        schnorr.verify(keyPair.publicKey, KAT.hash, badR),
        false,
      );
      assert.strictEqual(
        schnorr.verify(keyPair.publicKey, KAT.hash, badS),
        false,
      );
    });

    it('rejects a malformed public key', () => {
      const cases = [
        Buffer.alloc(33, 0x02), // x = 0x0202..., not on the curve
        Buffer.concat([Buffer.from([0x02]), Buffer.alloc(32, 0xff)]), // x >= p
        Buffer.concat([
          Buffer.from([0x02]),
          Buffer.alloc(31),
          Buffer.from([0x05]),
        ]), // x = 5, which has no square root
        Buffer.alloc(33, 0x04), // neither 0x02 nor 0x03
        Buffer.alloc(65, 0x05), // 65 bytes without the 0x04 prefix
        Buffer.alloc(20, 0x02), // neither 33 nor 65 bytes
      ];
      for (const publicKey of cases) {
        assert.strictEqual(
          schnorr.verify(publicKey, KAT.hash, signature),
          false,
        );
      }
    });

    it('rejects an uncompressed public key that is not on the curve', () => {
      // An uncompressed key states y as well as x, so nothing but an explicit
      // check keeps the pair on secp256k1. (0, 0) is the dangerous case: it
      // doubles to the point at infinity, so s*G - e*P collapses to s*G and
      // the public key drops out of the verification equation. Every signature
      // whose R = s*G has a quadratic-residue y then verifies against any
      // message. FORGERY is such a pair, found in one try for KAT.hash.
      const zero = Buffer.concat([
        Buffer.from([0x04]),
        Buffer.alloc(32),
        Buffer.alloc(32),
      ]);
      const FORGERY = Buffer.from(
        '065d07b01c79afe75cb7a5e9c497f7d9fc749f32bd1176724d749a58a9971a73' +
          'b5e509eb4bb0600fc75247ca58e088291afe5646695c5b222e8d48a2a362851a',
        'hex',
      );
      assert.strictEqual(schnorr.verify(zero, KAT.hash, FORGERY), false);

      const cases = [
        zero,
        // y = 1, which is not the square root of x^3 + 7 for x = 1.
        Buffer.concat([
          Buffer.from([0x04]),
          Buffer.alloc(31),
          Buffer.from([0x01]),
          Buffer.alloc(31),
          Buffer.from([0x01]),
        ]),
        // The x and y of a real point, swapped.
        Buffer.concat([
          Buffer.from([0x04]),
          keyPair.publicKey.slice(1),
          Buffer.alloc(32, 0x01),
        ]),
      ];
      for (const publicKey of cases) {
        assert.strictEqual(
          schnorr.verify(publicKey, KAT.hash, signature),
          false,
        );
      }
    });
  });
});
