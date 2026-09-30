import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as bitcoin from '../..';
const DEV = bitcoin.networks.dev;

describe('tapyrusjs-lib (addresses)', () => {
  it('can generate a random address', () => {
    const keyPair = bitcoin.ECPair.makeRandom();
    const { address } = bitcoin.payments.p2pkh({ pubkey: keyPair.publicKey });

    // prod P2PKH addresses start with a '1'
    assert.strictEqual(address!.startsWith('1'), true);
  });

  it('can import an address via WIF', () => {
    const keyPair = bitcoin.ECPair.fromWIF(
      'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn',
    );
    const { address } = bitcoin.payments.p2pkh({ pubkey: keyPair.publicKey });

    assert.strictEqual(address, '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH');
  });

  it('can generate a P2SH, pay-to-multisig (2-of-3) address', () => {
    const pubkeys = [
      '026477115981fe981a6918a6297d9803c4dc04f328f22041bedff886bbc2962e01',
      '02c96db2302d19b43d4c69368babace7854cc84eb9e061cde51cfa77ca4a22b8b9',
      '03c6103b3b83e4a24a0e33a4df246ef11772f9992663db0c35759a5e2ebf68d8e9',
    ].map(hex => Buffer.from(hex, 'hex'));
    const { address } = bitcoin.payments.p2sh({
      redeem: bitcoin.payments.p2ms({ m: 2, pubkeys }),
    });

    assert.strictEqual(address, '36NUkt6FWUi3LAWBqWRdDmdTWbt91Yvfu7');
  });

  // examples using other network information
  it('can generate a Dev mode address', () => {
    const keyPair = bitcoin.ECPair.makeRandom({ network: DEV });
    const { address } = bitcoin.payments.p2pkh({
      pubkey: keyPair.publicKey,
      network: DEV,
    });

    // dev mode P2PKH addresses start with a 'm' or 'n'
    assert.strictEqual(
      address!.startsWith('m') || address!.startsWith('n'),
      true,
    );
  });
});
