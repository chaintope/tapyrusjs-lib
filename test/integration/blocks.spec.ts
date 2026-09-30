import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as tapyrus from '../..';

describe('tapyrusjs-lib (blocks)', () => {
  it('can extract a height from a coinbase transaction', () => {
    // the coinbase of testnet block
    // 896574bee055370c047e911212f8472e7e77a1337d666e2a83da739d04f8de2a
    const txHex =
      '01000000010000000000000000000000000000000000000000000000000000000' +
      '000000000b64900000502b6490101ffffffff0100f2052a010000001976a91467' +
      '13b478d99432aac667b7d8e87f9d06edca03bb88ac00000000';
    const tx = tapyrus.Transaction.fromHex(txHex);

    assert.strictEqual(tx.ins.length, 1);
    const script = tx.ins[0].script;

    // the scriptSig opens with the height, as a minimally encoded push
    assert.strictEqual(script[0], 0x02);
    const height = tapyrus.script.number.decode(script.slice(1, 1 + script[0]));
    assert.strictEqual(height, 18870);

    // Tapyrus also puts the height in the outpoint index of the coinbase
    // input. Two coinbases at different heights therefore differ even when
    // they pay the same amount to the same address, which they have to:
    // hashMalFix ignores the scriptSig that BIP34 puts the height in.
    assert.strictEqual(tx.ins[0].index, height);
  });
});
