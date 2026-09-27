import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as tapyrus from '../..';
import { regtestUtils, Unspent } from './_regtest';

const NETWORK = regtestUtils.network;

// Every transaction carrying a colour needs a TPC input to pay the fee with:
// tapyrus-core rejects one without as bad-txns-token-without-fee. These tests
// fund the issuer with TPC, spend that one output, and leave the rest as
// change.
const FUNDING = 1e6;
const FEE = 1e4;

interface Issuer {
  key: tapyrus.ECPairInterface;
  payment: tapyrus.Payment;
  unspent: Unspent;
  prevTxHex: string;
}

/** Funds a fresh P2PKH key with TPC and returns what is needed to spend it. */
async function fundIssuer(): Promise<Issuer> {
  const key = tapyrus.ECPair.makeRandom({ network: NETWORK });
  const payment = tapyrus.payments.p2pkh({
    pubkey: key.publicKey,
    network: NETWORK,
  });
  const unspent = await regtestUtils.faucet(payment.address!, FUNDING);
  const { txHex } = await regtestUtils.fetch(unspent.txId);
  return { key, payment, unspent, prevTxHex: txHex };
}

/**
 * Builds, signs and broadcasts an issuance spending the issuer's TPC output.
 * The colour goes to `colored`, the leftover TPC back to the issuer.
 */
async function issue(
  issuer: Issuer,
  colored: { address: string; value: number },
): Promise<string> {
  const pstt = new tapyrus.Pstt({ network: NETWORK })
    .addInput({
      previousTxid: issuer.unspent.txId,
      outputIndex: issuer.unspent.vout,
      utxo: Buffer.from(issuer.prevTxHex, 'hex'),
    })
    .addOutput({ address: colored.address, amount: colored.value })
    .addOutput({ address: issuer.payment.address!, amount: FUNDING - FEE })
    .finishConstruction();
  pstt.signInput(0, issuer.key);

  assert.strictEqual(pstt.validateSignaturesOfInput(0), true);
  const tx = pstt.finalizeAllInputs().extractTransaction();

  await regtestUtils.broadcast(tx.toHex());
  await regtestUtils.mine(1);
  return tx.getId();
}

describe('tapyrusjs-lib (colored coins)', () => {
  it('can issue a reissuable token', async () => {
    const issuer = await fundIssuer();
    // the colour of a reissuable token is the script the issuance spends, so
    // the issuer can mint more later by spending to the same address again
    const colorId = tapyrus.coloridentifier.reissuable(issuer.payment.output!);
    const holder = tapyrus.payments.cp2pkh({
      pubkey: issuer.key.publicKey,
      colorId,
      network: NETWORK,
    });

    const txId = await issue(issuer, { address: holder.address!, value: 1e6 });

    const tx = await regtestUtils.fetch(txId);
    assert.strictEqual(tx.outs[0].token, colorId.toString('hex'));
    assert.strictEqual(tx.outs[0].value, 1e6);
    assert.strictEqual(tx.outs[1].token, 'TPC');
    assert.strictEqual(tx.outs[1].value, FUNDING - FEE);
  });

  it('can issue a non-reissuable token', async () => {
    const issuer = await fundIssuer();
    // the colour of a non-reissuable token is the output the issuance spends,
    // so the whole supply is fixed by this one transaction
    const colorId = tapyrus.coloridentifier.nonReissuable({
      txid: tapyrus.bufferutils.reverseBuffer(
        Buffer.from(issuer.unspent.txId, 'hex'),
      ),
      index: issuer.unspent.vout,
    });
    const holder = tapyrus.payments.cp2pkh({
      pubkey: issuer.key.publicKey,
      colorId,
      network: NETWORK,
    });

    const txId = await issue(issuer, { address: holder.address!, value: 500 });

    const tx = await regtestUtils.fetch(txId);
    assert.strictEqual(tx.outs[0].token, colorId.toString('hex'));
    assert.strictEqual(tx.outs[0].value, 500);
  });

  it('can issue an NFT', async () => {
    const issuer = await fundIssuer();
    const colorId = tapyrus.coloridentifier.nft({
      txid: tapyrus.bufferutils.reverseBuffer(
        Buffer.from(issuer.unspent.txId, 'hex'),
      ),
      index: issuer.unspent.vout,
    });
    const holder = tapyrus.payments.cp2pkh({
      pubkey: issuer.key.publicKey,
      colorId,
      network: NETWORK,
    });

    // an NFT output must carry exactly 1, and a transaction may hold exactly
    // one output of that colour
    const txId = await issue(issuer, { address: holder.address!, value: 1 });

    const tx = await regtestUtils.fetch(txId);
    assert.strictEqual(tx.outs[0].token, colorId.toString('hex'));
    assert.strictEqual(tx.outs[0].value, 1);
  });

  it('rejects an NFT that does not carry exactly one unit', async () => {
    const issuer = await fundIssuer();
    const colorId = tapyrus.coloridentifier.nft({
      txid: tapyrus.bufferutils.reverseBuffer(
        Buffer.from(issuer.unspent.txId, 'hex'),
      ),
      index: issuer.unspent.vout,
    });
    const holder = tapyrus.payments.cp2pkh({
      pubkey: issuer.key.publicKey,
      colorId,
      network: NETWORK,
    });

    await assert.rejects(
      issue(issuer, { address: holder.address!, value: 2 }),
      /bad-txns-nft-amount/,
    );
  });

  it('can transfer a token to another holder', async () => {
    const issuer = await fundIssuer();
    const colorId = tapyrus.coloridentifier.reissuable(issuer.payment.output!);
    const holder = tapyrus.payments.cp2pkh({
      pubkey: issuer.key.publicKey,
      colorId,
      network: NETWORK,
    });
    const issuanceId = await issue(issuer, {
      address: holder.address!,
      value: 1e6,
    });
    const issuance = await regtestUtils.fetch(issuanceId);

    // spend the colour and the TPC change together: the colour pays no fee
    const recipient = tapyrus.ECPair.makeRandom({ network: NETWORK });
    const recipientAddress = tapyrus.payments.cp2pkh({
      pubkey: recipient.publicKey,
      colorId,
      network: NETWORK,
    }).address!;

    const pstt = new tapyrus.Pstt({ network: NETWORK })
      .addInput({
        previousTxid: issuanceId,
        outputIndex: 0,
        utxo: Buffer.from(issuance.txHex, 'hex'),
      })
      .addInput({
        previousTxid: issuanceId,
        outputIndex: 1,
        utxo: Buffer.from(issuance.txHex, 'hex'),
      })
      .addOutput({ address: recipientAddress, amount: 1e6 })
      .addOutput({
        address: issuer.payment.address!,
        amount: FUNDING - 2 * FEE,
      })
      .finishConstruction();
    pstt.signInput(0, issuer.key);
    pstt.signInput(1, issuer.key);

    // Pstt's Input Finalizer already knows CP2PKH: it satisfies it with the
    // same {signature} {pubkey} stack as P2PKH.
    const tx = pstt.finalizeAllInputs().extractTransaction();

    await regtestUtils.broadcast(tx.toHex());
    await regtestUtils.mine(1);

    const transferred = await regtestUtils.fetch(tx.getId());
    assert.strictEqual(transferred.outs[0].token, colorId.toString('hex'));
    assert.strictEqual(transferred.outs[0].value, 1e6);
    assert.strictEqual(transferred.outs[0].address, recipientAddress);
  });

  it('can burn a token', async () => {
    const issuer = await fundIssuer();
    const colorId = tapyrus.coloridentifier.reissuable(issuer.payment.output!);
    const holder = tapyrus.payments.cp2pkh({
      pubkey: issuer.key.publicKey,
      colorId,
      network: NETWORK,
    });
    const issuanceId = await issue(issuer, {
      address: holder.address!,
      value: 1e6,
    });
    const issuance = await regtestUtils.fetch(issuanceId);

    // spending the colour without producing an output of that colour destroys
    // it; the TPC input still has to cover the fee
    const pstt = new tapyrus.Pstt({ network: NETWORK })
      .addInput({
        previousTxid: issuanceId,
        outputIndex: 0,
        utxo: Buffer.from(issuance.txHex, 'hex'),
      })
      .addInput({
        previousTxid: issuanceId,
        outputIndex: 1,
        utxo: Buffer.from(issuance.txHex, 'hex'),
      })
      .addOutput({
        address: issuer.payment.address!,
        amount: FUNDING - 2 * FEE,
      })
      .finishConstruction();
    pstt.signInput(0, issuer.key);
    pstt.signInput(1, issuer.key);

    const tx = pstt.finalizeAllInputs().extractTransaction();

    await regtestUtils.broadcast(tx.toHex());
    await regtestUtils.mine(1);

    const burned = await regtestUtils.fetch(tx.getId());
    assert.strictEqual(burned.outs.length, 1);
    assert.strictEqual(burned.outs[0].token, 'TPC');
  });

  it('can hold a token in a CP2SH output', async () => {
    const issuer = await fundIssuer();
    const colorId = tapyrus.coloridentifier.reissuable(issuer.payment.output!);

    // a 1-of-1 multisig, wrapped so that the colour sits on the script hash
    const redeem = tapyrus.payments.p2ms({
      m: 1,
      pubkeys: [issuer.key.publicKey],
      network: NETWORK,
    });
    const holder = tapyrus.payments.cp2sh({
      redeem,
      colorId,
      network: NETWORK,
    });

    const txId = await issue(issuer, { address: holder.address!, value: 700 });

    const tx = await regtestUtils.fetch(txId);
    assert.strictEqual(tx.outs[0].token, colorId.toString('hex'));
    assert.strictEqual(tx.outs[0].value, 700);
    assert.ok(tx.outs[0].script.equals(holder.output!));
  });
});
