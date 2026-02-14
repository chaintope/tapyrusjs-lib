import * as assert from 'assert';
import { describe, it, afterEach } from 'mocha';
import { ECPair, Metadata, NetworkId } from '..';
import * as fixtures from './fixtures/tip0020_metadata.json';

// Helper to determine tokenType based on test case
function getTokenType(f: any): 'reissuable' | 'nft' {
  const nftFields = ['image', 'animation_url', 'external_url', 'attributes'];
  const hasNftField = nftFields.some(field => f.metadata[field] !== undefined);
  return hasNftField ? 'nft' : 'reissuable';
}

const basePoint = Buffer.from((fixtures as any).base_point, 'hex');

describe('Metadata', () => {
  describe('valid test cases', () => {
    fixtures.valid_test_cases.forEach((f: any) => {
      it(f.name + ': ' + f.description, () => {
        const metadata = new Metadata({
          ...f.metadata,
          tokenType: getTokenType(f),
        });

        assert.strictEqual(metadata.toCanonical(), f.canonical);
        assert.strictEqual(metadata.digest().toString('hex'), f.hash);

        // P2C address derivation test
        if (f.p2c_address) {
          assert.strictEqual(metadata.p2cAddress(basePoint), f.p2c_address);
        }
      });
    });
  });

  describe('invalid test cases', () => {
    fixtures.invalid_test_cases.forEach((f: any) => {
      it(f.name + ': ' + f.description, () => {
        assert.throws(() => {
          new Metadata({ ...f.metadata, tokenType: getTokenType(f) });
        }, new RegExp(f.error));
      });
    });
  });

  describe('digest', () => {
    it('returns a 32-byte buffer', () => {
      const metadata = new Metadata({
        version: '1.0',
        name: 'Test Token',
        symbol: 'TEST',
        tokenType: 'reissuable',
      });
      const digest = metadata.digest();
      assert.strictEqual(digest.length, 32);
    });
  });

  describe('decimals handling', () => {
    it('excludes decimals=0 from canonical form', () => {
      const metadata = new Metadata({
        version: '1.0',
        name: 'Zero Decimals Token',
        symbol: 'ZERO',
        tokenType: 'reissuable',
        decimals: 0,
      });
      assert.strictEqual(metadata.decimals, undefined);
      const canonical = metadata.toCanonical();
      assert.ok(!canonical.includes('decimals'));
    });

    it('includes non-zero decimals in canonical form', () => {
      const metadata = new Metadata({
        version: '1.0',
        name: 'Test Token',
        symbol: 'TEST',
        tokenType: 'reissuable',
        decimals: 8,
      });
      assert.strictEqual(metadata.decimals, 8);
      const canonical = metadata.toCanonical();
      assert.ok(canonical.includes('"decimals":8'));
    });
  });

  describe('toObject', () => {
    it('returns MetadataFields object', () => {
      const metadata = new Metadata({
        version: '1.0',
        name: 'Test Token',
        symbol: 'TEST',
        tokenType: 'reissuable',
        decimals: 8,
        description: 'A test token',
      });
      const obj = metadata.toObject();
      assert.strictEqual(obj.version, '1.0');
      assert.strictEqual(obj.name, 'Test Token');
      assert.strictEqual(obj.symbol, 'TEST');
      assert.strictEqual(obj.tokenType, 'reissuable');
      assert.strictEqual(obj.decimals, 8);
      assert.strictEqual(obj.description, 'A test token');
    });

    it('excludes undefined fields', () => {
      const metadata = new Metadata({
        version: '1.0',
        name: 'Test Token',
        symbol: 'TEST',
        tokenType: 'nft',
      });
      const obj = metadata.toObject();
      assert.strictEqual(obj.decimals, undefined);
      assert.strictEqual(obj.description, undefined);
    });
  });

  describe('fromJSON', () => {
    it('parses JSON string and creates Metadata', () => {
      const json =
        '{"version":"1.0","name":"Test Token","symbol":"TEST","tokenType":"reissuable","decimals":8}';
      const metadata = Metadata.fromJSON(json);
      assert.strictEqual(metadata.version, '1.0');
      assert.strictEqual(metadata.name, 'Test Token');
      assert.strictEqual(metadata.symbol, 'TEST');
      assert.strictEqual(metadata.tokenType, 'reissuable');
      assert.strictEqual(metadata.decimals, 8);
    });

    it('throws on invalid JSON', () => {
      assert.throws(() => {
        Metadata.fromJSON('{"version":"1.0","name":"Test","tokenType":"reissuable"}');
      }, /symbol is required/);
    });
  });

  describe('commitment', () => {
    it('returns a 32-byte buffer', () => {
      const metadata = new Metadata({
        version: '1.0',
        name: 'Test Token',
        symbol: 'TEST',
        tokenType: 'reissuable',
      });
      const keyPair = ECPair.makeRandom();
      const commitment = metadata.commitment(keyPair.publicKey);
      assert.strictEqual(commitment.length, 32);
    });

    it('throws for invalid public key length', () => {
      const metadata = new Metadata({
        version: '1.0',
        name: 'Test Token',
        symbol: 'TEST',
        tokenType: 'reissuable',
      });
      assert.throws(() => {
        metadata.commitment(Buffer.alloc(32));
      }, /publicKey must be 33 bytes/);
    });

    it('produces deterministic commitment', () => {
      const metadata = new Metadata({
        version: '1.0',
        name: 'Test Token',
        symbol: 'TEST',
        tokenType: 'reissuable',
      });
      const publicKey = Buffer.from(
        '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
        'hex',
      );
      const c1 = metadata.commitment(publicKey);
      const c2 = metadata.commitment(publicKey);
      assert.deepStrictEqual(c1, c2);
    });
  });

  describe('p2cPublicKey', () => {
    it('returns a 33-byte compressed public key', () => {
      const metadata = new Metadata({
        version: '1.0',
        name: 'Test Token',
        symbol: 'TEST',
        tokenType: 'reissuable',
      });
      const keyPair = ECPair.makeRandom();
      const p2cPubKey = metadata.p2cPublicKey(keyPair.publicKey);
      assert.strictEqual(p2cPubKey.length, 33);
      assert.ok(p2cPubKey[0] === 0x02 || p2cPubKey[0] === 0x03);
    });

    it('produces different public key from original', () => {
      const metadata = new Metadata({
        version: '1.0',
        name: 'Test Token',
        symbol: 'TEST',
        tokenType: 'reissuable',
      });
      const keyPair = ECPair.makeRandom();
      const p2cPubKey = metadata.p2cPublicKey(keyPair.publicKey);
      assert.notDeepStrictEqual(p2cPubKey, keyPair.publicKey);
    });

    it('produces deterministic P2C public key', () => {
      const metadata = new Metadata({
        version: '1.0',
        name: 'Test Token',
        symbol: 'TEST',
        tokenType: 'reissuable',
      });
      const publicKey = Buffer.from(
        '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
        'hex',
      );
      const p2c1 = metadata.p2cPublicKey(publicKey);
      const p2c2 = metadata.p2cPublicKey(publicKey);
      assert.deepStrictEqual(p2c1, p2c2);
    });
  });

  describe('deriveColorId', () => {
    describe('reissuable', () => {
      it('returns a 33-byte color id starting with 0xc1', () => {
        const metadata = new Metadata({
          version: '1.0',
          name: 'Reissuable Token',
          symbol: 'REIS',
          tokenType: 'reissuable',
        });
        const keyPair = ECPair.makeRandom();
        const colorId = metadata.deriveColorId(keyPair.publicKey);
        assert.strictEqual(colorId.length, 33);
        assert.strictEqual(colorId[0], 0xc1);
      });

      it('throws without publicKey', () => {
        const metadata = new Metadata({
          version: '1.0',
          name: 'Reissuable Token',
          symbol: 'REIS',
          tokenType: 'reissuable',
        });
        assert.throws(() => {
          metadata.deriveColorId();
        }, /publicKey is required for reissuable token/);
      });

      it('produces deterministic color id', () => {
        const metadata = new Metadata({
          version: '1.0',
          name: 'Reissuable Token',
          symbol: 'REIS',
          tokenType: 'reissuable',
        });
        const publicKey = Buffer.from(
          '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
          'hex',
        );
        const c1 = metadata.deriveColorId(publicKey);
        const c2 = metadata.deriveColorId(publicKey);
        assert.deepStrictEqual(c1, c2);
      });
    });

    describe('non_reissuable', () => {
      it('returns a 33-byte color id starting with 0xc2', () => {
        const metadata = new Metadata({
          version: '1.0',
          name: 'Non-Reissuable Token',
          symbol: 'NREIS',
          tokenType: 'non_reissuable',
        });
        const outPoint = {
          txid: Buffer.alloc(32, 0x01),
          index: 0,
        };
        const colorId = metadata.deriveColorId(undefined, outPoint);
        assert.strictEqual(colorId.length, 33);
        assert.strictEqual(colorId[0], 0xc2);
      });

      it('throws without outPoint', () => {
        const metadata = new Metadata({
          version: '1.0',
          name: 'Non-Reissuable Token',
          symbol: 'NREIS',
          tokenType: 'non_reissuable',
        });
        assert.throws(() => {
          metadata.deriveColorId();
        }, /outPoint is required for non_reissuable token/);
      });
    });

    describe('nft', () => {
      it('returns a 33-byte color id starting with 0xc3', () => {
        const metadata = new Metadata({
          version: '1.0',
          name: 'NFT Token',
          symbol: 'NFT',
          tokenType: 'nft',
        });
        const outPoint = {
          txid: Buffer.alloc(32, 0x02),
          index: 1,
        };
        const colorId = metadata.deriveColorId(undefined, outPoint);
        assert.strictEqual(colorId.length, 33);
        assert.strictEqual(colorId[0], 0xc3);
      });

      it('throws without outPoint', () => {
        const metadata = new Metadata({
          version: '1.0',
          name: 'NFT Token',
          symbol: 'NFT',
          tokenType: 'nft',
        });
        assert.throws(() => {
          metadata.deriveColorId();
        }, /outPoint is required for nft token/);
      });
    });
  });

  describe('tokenType validation', () => {
    it('throws on missing tokenType', () => {
      assert.throws(() => {
        new Metadata({
          version: '1.0',
          name: 'Test Token',
          symbol: 'TEST',
        } as any);
      }, /tokenType is required/);
    });

    it('throws on invalid tokenType', () => {
      assert.throws(() => {
        new Metadata({
          version: '1.0',
          name: 'Test Token',
          symbol: 'TEST',
          tokenType: 'invalid' as any,
        });
      }, /tokenType must be reissuable, non_reissuable, or nft/);
    });
  });

  describe('NFT-only fields validation', () => {
    it('throws when image is used with reissuable', () => {
      assert.throws(() => {
        new Metadata({
          version: '1.0',
          name: 'Test Token',
          symbol: 'TEST',
          tokenType: 'reissuable',
          image: 'https://example.com/image.png',
        });
      }, /image is only allowed for nft token type/);
    });

    it('throws when animation_url is used with non_reissuable', () => {
      assert.throws(() => {
        new Metadata({
          version: '1.0',
          name: 'Test Token',
          symbol: 'TEST',
          tokenType: 'non_reissuable',
          animation_url: 'https://example.com/video.mp4',
        });
      }, /animation_url is only allowed for nft token type/);
    });

    it('throws when external_url is used with reissuable', () => {
      assert.throws(() => {
        new Metadata({
          version: '1.0',
          name: 'Test Token',
          symbol: 'TEST',
          tokenType: 'reissuable',
          external_url: 'https://example.com/nft/123',
        });
      }, /external_url is only allowed for nft token type/);
    });

    it('throws when attributes is used with reissuable', () => {
      assert.throws(() => {
        new Metadata({
          version: '1.0',
          name: 'Test Token',
          symbol: 'TEST',
          tokenType: 'reissuable',
          attributes: [{ trait_type: 'Color', value: 'Blue' }],
        });
      }, /attributes is only allowed for nft token type/);
    });

    it('allows NFT-only fields with nft tokenType', () => {
      const metadata = new Metadata({
        version: '1.0',
        name: 'NFT Token',
        symbol: 'NFT',
        tokenType: 'nft',
        image: 'https://example.com/image.png',
        animation_url: 'https://example.com/video.mp4',
        external_url: 'https://example.com/nft/123',
        attributes: [{ trait_type: 'Color', value: 'Blue' }],
      });
      assert.strictEqual(metadata.image, 'https://example.com/image.png');
      assert.strictEqual(metadata.animation_url, 'https://example.com/video.mp4');
      assert.strictEqual(metadata.external_url, 'https://example.com/nft/123');
      assert.deepStrictEqual(metadata.attributes, [{ trait_type: 'Color', value: 'Blue' }]);
    });
  });

  describe('fetch', () => {
    const originalFetch = global.fetch;

    afterEach(() => {
      global.fetch = originalFetch;
    });

    const validJson = JSON.stringify({
      version: '1.0',
      name: 'Test Token',
      symbol: 'TEST',
      tokenType: 'reissuable',
      decimals: 8,
    });

    const colorId = 'c1a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';

    it('fetches metadata from registry', async () => {
      global.fetch = (async (url: string) => {
        assert.strictEqual(
          url,
          `https://chaintope.github.io/tapyrus-token-registry/tokens/${NetworkId.TAPYRUS_API}/${colorId}.json`,
        );
        return {
          ok: true,
          status: 200,
          statusText: 'OK',
          text: async () => validJson,
        };
      }) as any;

      const metadata = await Metadata.fetch(colorId, NetworkId.TAPYRUS_API);
      assert.strictEqual(metadata.name, 'Test Token');
      assert.strictEqual(metadata.symbol, 'TEST');
      assert.strictEqual(metadata.tokenType, 'reissuable');
      assert.strictEqual(metadata.decimals, 8);
    });

    it('uses custom baseUrl', async () => {
      const customBase = 'https://custom.example.com/registry';
      global.fetch = (async (url: string) => {
        assert.strictEqual(
          url,
          `${customBase}/tokens/${NetworkId.TESTNET}/${colorId}.json`,
        );
        return {
          ok: true,
          status: 200,
          statusText: 'OK',
          text: async () => validJson,
        };
      }) as any;

      const metadata = await Metadata.fetch(
        colorId,
        NetworkId.TESTNET,
        customBase,
      );
      assert.strictEqual(metadata.name, 'Test Token');
    });

    it('throws on HTTP error', async () => {
      global.fetch = (async () => {
        return {
          ok: false,
          status: 404,
          statusText: 'Not Found',
          text: async () => 'Not Found',
        };
      }) as any;

      await assert.rejects(
        () => Metadata.fetch(colorId, NetworkId.TAPYRUS_API),
        /Failed to fetch metadata: 404 Not Found/,
      );
    });

    it('throws on network error', async () => {
      global.fetch = (async () => {
        throw new Error('Network error');
      }) as any;

      await assert.rejects(
        () => Metadata.fetch(colorId, NetworkId.TAPYRUS_API),
        /Network error/,
      );
    });

    it('throws on invalid JSON response', async () => {
      global.fetch = (async () => {
        return {
          ok: true,
          status: 200,
          statusText: 'OK',
          text: async () => 'not json',
        };
      }) as any;

      await assert.rejects(
        () => Metadata.fetch(colorId, NetworkId.TAPYRUS_API),
      );
    });

    it('infers tokenType from colorId prefix', async () => {
      const registryJson = JSON.stringify({
        version: '1.0',
        name: 'Tapyrus Simple Token',
        symbol: 'TST',
        icon: 'https://www.chaintope.com/wp-content/themes/chaintope20250603/_asset/img/products/tapyrus/tapyrus__icon01.png',
      });
      const registryColorId =
        'c1a1f1f07fc9526cb3e9610117359d2e8e0468089dba599822759f7ddd92efeaa8';
      global.fetch = (async (url: string) => {
        assert.strictEqual(
          url,
          `https://chaintope.github.io/tapyrus-token-registry/tokens/${NetworkId.TESTNET}/${registryColorId}.json`,
        );
        return {
          ok: true,
          status: 200,
          statusText: 'OK',
          text: async () => registryJson,
        };
      }) as any;

      const metadata = await Metadata.fetch(
        registryColorId,
        NetworkId.TESTNET,
      );
      assert.strictEqual(metadata.name, 'Tapyrus Simple Token');
      assert.strictEqual(metadata.symbol, 'TST');
      assert.strictEqual(metadata.tokenType, 'reissuable');
      assert.strictEqual(
        metadata.icon,
        'https://www.chaintope.com/wp-content/themes/chaintope20250603/_asset/img/products/tapyrus/tapyrus__icon01.png',
      );
    });
  });
});
