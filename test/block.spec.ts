import * as assert from 'assert';
import { beforeEach, describe, it } from 'mocha';
import { Block } from '..';

import * as fixtures from './fixtures/block.json';

describe('Block', () => {
  describe('fromBuffer/fromHex', () => {
    fixtures.valid.forEach(f => {
      it('imports ' + f.description, () => {
        const block = Block.fromHex(f.hex);

        assert.strictEqual(block.features, f.features);
        assert.strictEqual(block.prevHash!.toString('hex'), f.prevHash);
        assert.strictEqual(block.merkleRoot!.toString('hex'), f.merkleRoot);
        assert.strictEqual(block.imMerkleRoot!.toString('hex'), f.imMerkleRoot);
        assert.strictEqual(block.timestamp, f.timestamp);
        assert.strictEqual(block.xfield.type, f.xfieldType);
        assert.strictEqual(block.proof.toString('hex'), f.proof);
        assert.strictEqual(block.transactions!.length, f.transactions);
        assert.strictEqual(block.byteLength(true), f.headerLength);
        assert.strictEqual(block.byteLength(false), f.hex.length / 2);
      });
    });

    it('reads the aggregate public key of an xfield', () => {
      const f = fixtures.valid.find(x => x.xfieldType === 1)!;
      const block = Block.fromHex(f.hex);

      assert.strictEqual(
        block.xfield.aggregatePubkey!.toString('hex'),
        f.aggregatePubkey,
      );
    });

    fixtures.invalid.forEach(f => {
      it('throws on ' + f.exception, () => {
        assert.throws(() => {
          Block.fromHex(f.hex);
        }, new RegExp(f.exception));
      });
    });
  });

  describe('toBuffer/toHex', () => {
    fixtures.valid.forEach(f => {
      let block: Block;

      beforeEach(() => {
        block = Block.fromHex(f.hex);
      });

      it('exports ' + f.description, () => {
        assert.strictEqual(
          block.toHex(true),
          f.hex.slice(0, f.headerLength * 2),
        );
        assert.strictEqual(block.toHex(), f.hex);
      });
    });
  });

  describe('getHash/getId', () => {
    fixtures.valid.forEach(f => {
      it('returns ' + f.id + ' for ' + f.description, () => {
        const block = Block.fromHex(f.hex);

        assert.strictEqual(block.getHash().toString('hex'), f.hash);
        assert.strictEqual(block.getId(), f.id);
      });
    });
  });

  describe('getHashForSign', () => {
    fixtures.valid.forEach(f => {
      it('excludes the proof for ' + f.id, () => {
        const block = Block.fromHex(f.hex);

        assert.strictEqual(
          block.getHashForSign().toString('hex'),
          f.hashForSign,
        );
        // the proof is what makes the two hashes differ
        assert.notStrictEqual(f.hashForSign, f.hash);
      });
    });
  });

  describe('getUTCDate', () => {
    fixtures.valid.forEach(f => {
      it('returns UTC date of ' + f.id, () => {
        const block = Block.fromHex(f.hex);

        assert.strictEqual(block.getUTCDate().getTime(), f.timestamp * 1e3);
      });
    });
  });

  describe('calculateMerkleRoot', () => {
    it('should throw on zero-length transaction array', () => {
      assert.throws(() => {
        Block.calculateMerkleRoot([]);
      }, /Cannot compute merkle root for zero transactions/);

      assert.throws(() => {
        Block.calculateImMerkleRoot([]);
      }, /Cannot compute merkle root for zero transactions/);
    });

    fixtures.valid.forEach(f => {
      let block: Block;

      beforeEach(() => {
        block = Block.fromHex(f.hex);
      });

      it('returns both roots for ' + f.id, () => {
        assert.strictEqual(
          Block.calculateMerkleRoot(block.transactions!).toString('hex'),
          f.merkleRoot,
        );
        assert.strictEqual(
          Block.calculateImMerkleRoot(block.transactions!).toString('hex'),
          f.imMerkleRoot,
        );
      });
    });
  });

  describe('checkMerkleRoot', () => {
    fixtures.valid.forEach(f => {
      it('returns true for ' + f.id, () => {
        const block = Block.fromHex(f.hex);

        assert.strictEqual(block.checkMerkleRoot(), true);
      });
    });

    it('returns false when a root does not match', () => {
      const block = Block.fromHex(fixtures.valid[0].hex);
      block.imMerkleRoot = Buffer.alloc(32, 0xff);

      assert.strictEqual(block.checkMerkleRoot(), false);
    });
  });

  describe('checkProof', () => {
    // the genesis block carries the aggregate public key it is signed with
    const f = fixtures.valid.find(x => x.aggregatePubkey)!;
    const aggregatePubkey = Buffer.from(f.aggregatePubkey!, 'hex');

    it('accepts the signature of ' + f.id, () => {
      const block = Block.fromHex(f.hex);

      assert.strictEqual(block.checkProof(aggregatePubkey), true);
    });

    it('rejects the signature under another key', () => {
      const block = Block.fromHex(f.hex);
      const other = Buffer.from(
        '02bb8a7fbba7da4e6a0519296e30211c33c7307ac19aba4e8f56cce2d3da36b751',
        'hex',
      );

      assert.strictEqual(block.checkProof(other), false);
    });

    it('rejects a proof of the wrong length', () => {
      const block = Block.fromHex(f.hex);
      block.proof = block.proof.slice(0, 63);

      assert.strictEqual(block.checkProof(aggregatePubkey), false);
    });

    it('rejects a features value other than 1', () => {
      const block = Block.fromHex(f.hex);
      block.features = 2;

      assert.strictEqual(block.checkProof(aggregatePubkey), false);
    });

    it('rejects a tampered header', () => {
      const block = Block.fromHex(f.hex);
      block.timestamp += 1;

      assert.strictEqual(block.checkProof(aggregatePubkey), false);
    });
  });
});
