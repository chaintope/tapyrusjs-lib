import * as assert from 'assert';
import { describe, it } from 'mocha';
import { coloridentifier, payments } from '..';

// The two vectors tapyrus-core asserts in src/test/coloridentifier_tests.cpp
// (coloridentifier_string_conversion).
const REISSUABLE_SCRIPT = Buffer.from(
  '21c38282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508',
  'hex',
);
const REISSUABLE_COLOR_ID =
  'c1f335bd3240ddfd87a2c2fc5a53210606460f19143f5e475729c46e06fcc9858f';

const OUT_POINT = {
  txid: Buffer.from(
    '485273f6703f038a234400edadb543eb44b4af5372e8b207990beebc386e7954',
    'hex',
  ),
  index: 0,
};
const NON_REISSUABLE_COLOR_ID =
  'c29608951ee23595caa227e7668e39f9d3525a39e9dc30d7391f138576c07be84d';

describe('coloridentifier', () => {
  describe('reissuable', () => {
    it('matches the tapyrus-core vector', () => {
      assert.strictEqual(
        coloridentifier.reissuable(REISSUABLE_SCRIPT).toString('hex'),
        REISSUABLE_COLOR_ID,
      );
    });

    it('rejects a non-Buffer script', () => {
      assert.throws(() => {
        coloridentifier.reissuable('not a buffer' as any);
      }, /Expected Buffer/);
    });

    it('accepts a script whose push data holds the OP_COLOR byte', () => {
      const script = Buffer.from([0x01, 0xbc]);
      assert.strictEqual(coloridentifier.reissuable(script).length, 33);
    });

    it('rejects a coloured script', () => {
      const colorId = Buffer.from(REISSUABLE_COLOR_ID, 'hex');
      const hash = Buffer.alloc(20, 0x01);
      const coloured = [
        payments.cp2pkh({ hash, colorId }).output!,
        payments.cp2sh({ hash, colorId }).output!,
      ];
      // OP_COLOR is refused wherever it sits in the script.
      coloured.push(Buffer.from([0x76, 0xbc, 0x51]));
      coloured.forEach(script => {
        assert.throws(() => {
          coloridentifier.reissuable(script);
        }, /must not be a colored script/);
      });
    });
  });

  describe('nonReissuable', () => {
    it('matches the tapyrus-core vector', () => {
      assert.strictEqual(
        coloridentifier.nonReissuable(OUT_POINT).toString('hex'),
        NON_REISSUABLE_COLOR_ID,
      );
    });

    it('takes the index into account', () => {
      const other = coloridentifier.nonReissuable({
        txid: OUT_POINT.txid,
        index: 1,
      });
      assert.notStrictEqual(other.toString('hex'), NON_REISSUABLE_COLOR_ID);
    });

    it('rejects a txid that is not 32 bytes', () => {
      assert.throws(() => {
        coloridentifier.nonReissuable({ txid: Buffer.alloc(31), index: 0 });
      }, /of type Buffer\(Length: 32\)/);
    });

    it('rejects an index outside uint32', () => {
      assert.throws(() => {
        coloridentifier.nonReissuable({ txid: OUT_POINT.txid, index: -1 });
      }, /of type UInt32/);
    });
  });

  describe('nft', () => {
    it('keeps the serialization byte order of the txid', () => {
      // Same outPoint as the tapyrus-core non-reissuable vector, whose txid
      // is not a palindrome, so reversing it would change the result.
      assert.strictEqual(
        coloridentifier.nft(OUT_POINT).toString('hex'),
        'c3' + NON_REISSUABLE_COLOR_ID.slice(2),
      );
    });

    it('matches the tapyrusrb vector', () => {
      // tapyrusrb spec/tapyrus/script/color_spec.rb
      assert.strictEqual(
        coloridentifier
          .nft({ txid: Buffer.alloc(32, 0x01), index: 1 })
          .toString('hex'),
        'c3ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46',
      );
    });

    it('differs from nonReissuable only in the type byte', () => {
      const id = coloridentifier.nft(OUT_POINT);
      assert.strictEqual(id[0], 0xc3);
      assert.strictEqual(
        id.slice(1).toString('hex'),
        NON_REISSUABLE_COLOR_ID.slice(2),
      );
    });
  });

  it('always returns 33 bytes', () => {
    assert.strictEqual(
      coloridentifier.reissuable(REISSUABLE_SCRIPT).length,
      33,
    );
    assert.strictEqual(coloridentifier.nonReissuable(OUT_POINT).length, 33);
    assert.strictEqual(coloridentifier.nft(OUT_POINT).length, 33);
  });
});
