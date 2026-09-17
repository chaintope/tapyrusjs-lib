import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as baddress from '../src/address';
import * as bscript from '../src/script';
import * as fixtures from './fixtures/address.json';

const NETWORKS = require('../src/networks');

describe('address', () => {
  describe('fromBase58Check', () => {
    fixtures.standard.forEach(f => {
      if (!f.base58check) return;

      it('decodes ' + f.base58check, () => {
        const decode = baddress.fromBase58Check(f.base58check);

        assert.strictEqual(decode.version, f.version);
        assert.strictEqual(decode.hash.toString('hex'), f.hash);
        if (f.colorId) {
          assert.strictEqual(decode.colorId!.toString('hex'), f.colorId);
        }
      });
    });

    fixtures.invalid.fromBase58Check.forEach(f => {
      it('throws on ' + f.exception, () => {
        assert.throws(() => {
          baddress.fromBase58Check(f.address);
        }, new RegExp(f.address + ' ' + f.exception));
      });
    });
  });

  describe('fromOutputScript', () => {
    fixtures.standard.forEach(f => {
      it('encodes ' + f.script.slice(0, 30) + '... (' + f.network + ')', () => {
        const script = bscript.fromASM(f.script);
        const address = baddress.fromOutputScript(script, NETWORKS[f.network]);

        assert.strictEqual(address, f.base58check);
      });
    });

    fixtures.invalid.fromOutputScript.forEach(f => {
      it('throws when ' + f.script.slice(0, 30) + '... ' + f.exception, () => {
        const script = bscript.fromASM(f.script);

        assert.throws(() => {
          baddress.fromOutputScript(script);
        }, new RegExp(f.exception));
      });
    });
  });

  describe('color identifier', () => {
    const hash = Buffer.from('1111111111111111111111111111111111111111', 'hex');
    const colorId = Buffer.from(
      'c32222222222222222222222222222222222222222222222222222222222222222',
      'hex',
    );

    ['00', 'c0', 'c4'].forEach(typeByte => {
      it('rejects the type byte 0x' + typeByte, () => {
        const invalid = Buffer.concat([
          Buffer.from(typeByte, 'hex'),
          colorId.slice(1),
        ]);

        assert.throws(() => {
          baddress.toBase58Check(hash, 1, invalid);
        }, new RegExp('color identifier'));
      });
    });

    it('rejects an all-zero payload', () => {
      const zero = Buffer.concat([Buffer.from('c1', 'hex'), Buffer.alloc(32)]);

      assert.throws(() => {
        baddress.toBase58Check(hash, 1, zero);
      }, new RegExp('color identifier'));
    });

    it('rejects a colorId that is not 33 bytes', () => {
      assert.throws(() => {
        baddress.toBase58Check(hash, 1, colorId.slice(0, 32));
      }, new RegExp('color identifier'));
    });

    it('round-trips a valid color identifier', () => {
      const encoded = baddress.toBase58Check(hash, 1, colorId);
      const decoded = baddress.fromBase58Check(encoded);

      assert.strictEqual(decoded.version, 1);
      assert.strictEqual(decoded.hash.toString('hex'), hash.toString('hex'));
      assert.strictEqual(
        decoded.colorId!.toString('hex'),
        colorId.toString('hex'),
      );
    });
  });

  describe('toBase58Check', () => {
    fixtures.standard.forEach(f => {
      if (!f.base58check) return;

      it('encodes ' + f.hash + ' (' + f.network + ')', () => {
        const colorId = f.colorId ? Buffer.from(f.colorId, 'hex') : undefined;
        const address = baddress.toBase58Check(
          Buffer.from(f.hash, 'hex'),
          f.version,
          colorId,
        );

        assert.strictEqual(address, f.base58check);
      });
    });
  });

  describe('toOutputScript', () => {
    fixtures.standard.forEach(f => {
      it('decodes ' + f.script.slice(0, 30) + '... (' + f.network + ')', () => {
        const script = baddress.toOutputScript(
          f.base58check,
          NETWORKS[f.network],
        );

        assert.strictEqual(bscript.toASM(script), f.script);
      });
    });

    fixtures.invalid.toOutputScript.forEach(f => {
      it('throws when ' + f.exception, () => {
        assert.throws(() => {
          baddress.toOutputScript(f.address);
        }, new RegExp(f.address + ' ' + f.exception));
      });
    });
  });
});
