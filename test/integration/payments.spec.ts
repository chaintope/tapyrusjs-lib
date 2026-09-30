import { describe, it } from 'mocha';
import * as bitcoin from '../..';
import { regtestUtils } from './_regtest';
const NETWORK = regtestUtils.network;
const keyPairs = [
  bitcoin.ECPair.makeRandom({ network: NETWORK }),
  bitcoin.ECPair.makeRandom({ network: NETWORK }),
];

async function buildAndSign(
  depends: any,
  prevOutput: any,
  redeemScript: any,
): Promise<string> {
  const unspent = await regtestUtils.faucetComplex(prevOutput, 5e4);
  const utx = await regtestUtils.fetch(unspent.txId);

  const pstt = new bitcoin.Pstt({ network: NETWORK })
    .addInput({
      previousTxid: unspent.txId,
      outputIndex: unspent.vout,
      utxo: Buffer.from(utx.txHex, 'hex'),
      ...(redeemScript ? { redeemScript } : {}),
    })
    .addOutput({
      address: regtestUtils.RANDOM_ADDRESS,
      amount: 2e4,
    })
    .finishConstruction();

  if (depends.signatures) {
    keyPairs.forEach(keyPair => {
      pstt.signInput(0, keyPair);
    });
  } else if (depends.signature) {
    pstt.signInput(0, keyPairs[0]);
  }

  return regtestUtils.broadcast(
    pstt
      .finalizeAllInputs()
      .extractTransaction()
      .toHex(),
  );
}

['p2ms', 'p2pk', 'p2pkh'].forEach(k => {
  const fixtures = require('../fixtures/' + k);
  const { depends } = fixtures.dynamic;
  const fn: any = (bitcoin.payments as any)[k];

  const base: any = {};
  if (depends.pubkey) base.pubkey = keyPairs[0].publicKey;
  if (depends.pubkeys) base.pubkeys = keyPairs.map(x => x.publicKey);
  if (depends.m) base.m = base.pubkeys.length;

  const { output } = fn(base);
  if (!output) throw new TypeError('Missing output');

  describe('tapyrusjs-lib (payments - ' + k + ')', () => {
    it('can broadcast as an output, and be spent as an input', async () => {
      Object.assign(depends, { prevOutScriptType: k });
      await buildAndSign(depends, output, undefined);
    });

    it(
      'can (as P2SH(' +
        k +
        ')) broadcast as an output, and be spent as an input',
      async () => {
        const p2sh = bitcoin.payments.p2sh({
          redeem: { output },
          network: NETWORK,
        });
        Object.assign(depends, { prevOutScriptType: 'p2sh-' + k });
        await buildAndSign(depends, p2sh.output, p2sh.redeem!.output);
      },
    );
  });
});
