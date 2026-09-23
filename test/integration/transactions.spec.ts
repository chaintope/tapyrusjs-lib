import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as bitcoin from '../..';
import { regtestUtils } from './_regtest';
const rng = require('randombytes');
const regtest = regtestUtils.network;

const { bip32 } = bitcoin;

// See bottom of file for some helper functions used to make the payment objects needed.

describe('tapyrusjs-lib (transactions with psbt)', () => {
  it('can create a 1-to-1 Transaction', () => {
    const alice = bitcoin.ECPair.fromWIF(
      'L2uPYXe17xSTqbCjZvL2DsyXPCbXspvcu5mHLDYUgzdUbZGSKrSr',
    );
    const psbt = new bitcoin.Psbt();
    psbt.setVersion(1); // Tapyrus calls this nFeatures and only accepts 1.
    psbt.setLocktime(0); // This is the default. This line is not needed.
    psbt.addInput({
      // if hash is string, txid, if hash is Buffer, is reversed compared to txid
      hash: '7f1872722325c9b9516938df4b0eb0174f6c3385c5c92aac806efc062ead52ed',
      index: 0,
      sequence: 0xffffffff, // These are defaults. This line is not needed.

      // an input requires passing the whole previous tx as Buffer
      nonWitnessUtxo: Buffer.from(
        '0100000001f9f34e95b9d5c8abcd20fc5bd4a825d1517be62f0f775e5f36da944d9' +
          '452e550000000006b483045022100c86e9a111afc90f64b4904bd609e9eaed80d48' +
          'ca17c162b1aca0a788ac3526f002207bb79b60d4fc6526329bf18a77135dc566020' +
          '9e761da46e1c2f1152ec013215801210211755115eabf846720f5cb18f248666fec' +
          '631e5e1e66009ce3710ceea5b1ad13ffffffff01' +
          // value in satoshis (Int64LE) = 0x015f90 = 90000
          '905f010000000000' +
          // scriptPubkey length
          '19' +
          // scriptPubkey
          '76a9148bbc95d2709c71607c60ee3f097c1217482f518d88ac' +
          // locktime
          '00000000',
        'hex',
      ),

      // Not featured here:
      //   redeemScript. A Buffer of the redeemScript for P2SH
    });
    psbt.addOutput({
      address: '1KRMKfeZcmosxALVYESdPNez1AP1mEtywp',
      value: 80000,
    });
    psbt.signInput(0, alice);
    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    psbt.finalizeAllInputs();
    assert.strictEqual(
      psbt.extractTransaction().toHex(),
      '0100000001ed52ad2e06fc6e80ac2ac9c585336c4f17b00e4bdf386951b9c92523727' +
        '2187f000000006b483045022100bd770468f607937fccd795c773344a4fe8440efd2a' +
        'ef6c5adfa23b38a2178c9602207ee86c0c33de38cf7e9793ff6044a81c71887016c68' +
        '6bec5b5e63341bc5ed46001210365db9da3f8a260078a7e8f8b708a1161468fb2323f' +
        'fda5ec16b261ec1056f455ffffffff0180380100000000001976a914ca0d36044e0dc' +
        '08a22724efa6f6a07b0ec4c79aa88ac00000000',
    );
  });

  it('can create (and broadcast to a node) a typical Transaction', async () => {
    // these are { payment: Payment; keys: ECPair[] }
    const alice1 = createPayment('p2pkh');
    const alice2 = createPayment('p2pkh');

    // give Alice 2 unspent outputs
    const inputData1 = await getInputData(5e4, alice1.payment, 'noredeem');
    const inputData2 = await getInputData(7e4, alice2.payment, 'noredeem');
    {
      const {
        hash, // string of txid or Buffer of tx hash. (txid and hash are reverse order)
        index, // the output index of the txo you are spending
        nonWitnessUtxo, // the full previous transaction as a Buffer
      } = inputData1;
      assert.deepStrictEqual({ hash, index, nonWitnessUtxo }, inputData1);
    }

    // network is only needed if you pass an address to addOutput
    // using script (Buffer of scriptPubkey) instead will avoid needed network.
    const psbt = new bitcoin.Psbt({ network: regtest })
      .addInput(inputData1) // alice1 unspent
      .addInput(inputData2) // alice2 unspent
      .addOutput({
        address: 'mwCwTceJvYV27KXBc3NJZys6CjsgsoeHmf',
        value: 8e4,
      }) // the actual "spend"
      .addOutput({
        address: alice2.payment.address, // OR script, which is a Buffer.
        value: 1e4,
      }); // Alice's change
    // (in)(5e4 + 7e4) - (out)(8e4 + 1e4) = (fee)3e4 = 30000, this is the miner fee

    // Let's show a new feature with PSBT.
    // We can have multiple signers sign in parrallel and combine them.
    // (this is not necessary, but a nice feature)

    // encode to send out to the signers
    const psbtBaseText = psbt.toBase64();

    // each signer imports
    const signer1 = bitcoin.Psbt.fromBase64(psbtBaseText);
    const signer2 = bitcoin.Psbt.fromBase64(psbtBaseText);

    // Alice signs each input with the respective private keys
    // signInput and signInputAsync are better
    // (They take the input index explicitly as the first arg)
    signer1.signAllInputs(alice1.keys[0]);
    signer2.signAllInputs(alice2.keys[0]);

    // If your signer object's sign method returns a promise, use the following
    // await signer2.signAllInputsAsync(alice2.keys[0])

    // encode to send back to combiner (signer 1 and 2 are not near each other)
    const s1text = signer1.toBase64();
    const s2text = signer2.toBase64();

    const final1 = bitcoin.Psbt.fromBase64(s1text);
    const final2 = bitcoin.Psbt.fromBase64(s2text);

    // final1.combine(final2) would give the exact same result
    psbt.combine(final1, final2);

    // Finalizer wants to check all signatures are valid before finalizing.
    // If the finalizer wants to check for specific pubkeys, the second arg
    // can be passed. See the first multisig example below.
    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    assert.strictEqual(psbt.validateSignaturesOfInput(1), true);

    // This step it new. Since we separate the signing operation and
    // the creation of the scriptSig and witness stack, we are able to
    psbt.finalizeAllInputs();

    // build and broadcast to the Tapyrus node
    await regtestUtils.broadcast(psbt.extractTransaction().toHex());
  });

  it('can create (and broadcast to a node) a Transaction with an OP_RETURN output', async () => {
    const alice1 = createPayment('p2pkh');
    const inputData1 = await getInputData(2e5, alice1.payment, 'noredeem');

    const data = Buffer.from('tapyrusjs-lib', 'utf8');
    const embed = bitcoin.payments.embed({ data: [data] });

    const psbt = new bitcoin.Psbt({ network: regtest })
      .addInput(inputData1)
      .addOutput({
        script: embed.output!,
        value: 1000,
      })
      .addOutput({
        address: regtestUtils.RANDOM_ADDRESS,
        value: 1e5,
      })
      .signInput(0, alice1.keys[0]);

    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    psbt.finalizeAllInputs();

    // build and broadcast to the Tapyrus node
    await regtestUtils.broadcast(psbt.extractTransaction().toHex());
  });

  it('can create (and broadcast to a node) a Transaction, w/ a P2SH(P2MS(2 of 4)) (multisig) input', async () => {
    const multisig = createPayment('p2sh-p2ms(2 of 4)');
    const inputData1 = await getInputData(2e4, multisig.payment, 'p2sh');
    {
      const {
        hash,
        index,
        nonWitnessUtxo,
        redeemScript, // NEW: P2SH needs to give redeemScript when adding an input.
      } = inputData1;
      assert.deepStrictEqual(
        { hash, index, nonWitnessUtxo, redeemScript },
        inputData1,
      );
    }

    const psbt = new bitcoin.Psbt({ network: regtest })
      .addInput(inputData1)
      .addOutput({
        address: regtestUtils.RANDOM_ADDRESS,
        value: 1e4,
      })
      .signInput(0, multisig.keys[0])
      .signInput(0, multisig.keys[2]);

    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    assert.strictEqual(
      psbt.validateSignaturesOfInput(0, multisig.keys[0].publicKey),
      true,
    );
    assert.throws(() => {
      psbt.validateSignaturesOfInput(0, multisig.keys[3].publicKey);
    }, new RegExp('No signatures for this pubkey'));
    psbt.finalizeAllInputs();

    const tx = psbt.extractTransaction();

    // build and broadcast to the Tapyrus node
    await regtestUtils.broadcast(tx.toHex());
    const txHash = bitcoin.bufferutils
      .reverseBuffer(tx.getHash())
      .toString('hex');
    await regtestUtils.verify({
      txId: txHash,
      address: regtestUtils.RANDOM_ADDRESS,
      vout: 0,
      value: 1e4,
    });
  });

  it(
    'can create (and broadcast to a node) a Transaction, w/ a ' +
      'P2SH(P2MS(2 of 2)) input with nonWitnessUtxo',
    async () => {
      const myKey = bitcoin.ECPair.makeRandom({ network: regtest });
      const myKeys = [
        myKey,
        bitcoin.ECPair.fromPrivateKey(myKey.privateKey!, { network: regtest }),
      ];
      const p2sh = createPayment('p2sh-p2ms(2 of 2)', myKeys);
      const inputData = await getInputData(5e4, p2sh.payment, 'p2sh');
      const psbt = new bitcoin.Psbt({ network: regtest })
        .addInput(inputData)
        .addOutput({
          address: regtestUtils.RANDOM_ADDRESS,
          value: 2e4,
        })
        .signInput(0, p2sh.keys[0]);
      psbt.finalizeAllInputs();
      const tx = psbt.extractTransaction();
      await regtestUtils.broadcast(tx.toHex());
      const txHash = bitcoin.bufferutils
        .reverseBuffer(tx.getHash())
        .toString('hex');
      await regtestUtils.verify({
        txId: txHash,
        address: regtestUtils.RANDOM_ADDRESS,
        vout: 0,
        value: 2e4,
      });
    },
  );

  it('can create (and broadcast to a node) a Transaction, w/ a P2PKH input using HD', async () => {
    const hdRoot = bip32.fromSeed(rng(64));
    const masterFingerprint = Buffer.from(hdRoot.fingerprint);
    const path = "m/44'/0'/0'/0/0";
    const childNode = hdRoot.derivePath(path);
    const pubkey = Buffer.from(childNode.publicKey);

    // This information should be added to your input via updateInput
    // You can add multiple bip32Derivation objects for multisig, but
    // each must have a unique pubkey.
    //
    // This is useful because as long as you store the masterFingerprint on
    // the PSBT Creator's server, you can have the PSBT Creator do the heavy
    // lifting with derivation from your m/44'/0'/0' xpub, (deriving only 0/0 )
    // and your signer just needs to pass in an HDSigner interface (ie. bip32 library)
    const updateData = {
      bip32Derivation: [
        {
          masterFingerprint,
          path,
          pubkey,
        },
      ],
    };
    const p2pkh = createPayment('p2pkh', [childNode as any]);
    const inputData = await getInputData(5e4, p2pkh.payment, 'noredeem');
    {
      const { hash, index, nonWitnessUtxo } = inputData;
      assert.deepStrictEqual({ hash, index, nonWitnessUtxo }, inputData);
    }

    // You can add extra attributes for updateData into the addInput(s) object(s)
    Object.assign(inputData, updateData);

    const psbt = new bitcoin.Psbt({ network: regtest })
      .addInput(inputData)
      // .updateInput(0, updateData) // if you didn't merge the bip32Derivation with inputData
      .addOutput({
        address: regtestUtils.RANDOM_ADDRESS,
        value: 2e4,
      })
      .signInputHD(0, hdRoot as any); // must sign with root!!!

    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    assert.strictEqual(psbt.validateSignaturesOfInput(0, pubkey), true);
    psbt.finalizeAllInputs();

    const tx = psbt.extractTransaction();

    // build and broadcast to the Tapyrus node
    await regtestUtils.broadcast(tx.toHex());
    const txHash = bitcoin.bufferutils
      .reverseBuffer(tx.getHash())
      .toString('hex');
    await regtestUtils.verify({
      txId: txHash,
      address: regtestUtils.RANDOM_ADDRESS,
      vout: 0,
      value: 2e4,
    });
  });
});

function createPayment(_type: string, myKeys?: any[], network?: any): any {
  network = network || regtest;
  const splitType = _type.split('-').reverse();
  const isMultisig = splitType[0].slice(0, 4) === 'p2ms';
  const keys = myKeys || [];
  let m: number | undefined;
  if (isMultisig) {
    const match = splitType[0].match(/^p2ms\((\d+) of (\d+)\)$/);
    m = parseInt(match![1], 10);
    let n = parseInt(match![2], 10);
    if (keys.length > 0 && keys.length !== n) {
      throw new Error('Need n keys for multisig');
    }
    while (!myKeys && n > 1) {
      keys.push(bitcoin.ECPair.makeRandom({ network }));
      n--;
    }
  }
  if (!myKeys) keys.push(bitcoin.ECPair.makeRandom({ network }));

  let payment: any;
  splitType.forEach(type => {
    if (type.slice(0, 4) === 'p2ms') {
      payment = bitcoin.payments.p2ms({
        m,
        pubkeys: keys.map(key => key.publicKey).sort((a, b) => a.compare(b)),
        network,
      });
    } else if (type === 'p2sh') {
      payment = (bitcoin.payments as any)[type]({
        redeem: payment,
        network,
      });
    } else {
      payment = (bitcoin.payments as any)[type]({
        pubkey: keys[0].publicKey,
        network,
      });
    }
  });

  return {
    payment,
    keys,
  };
}

async function getInputData(
  amount: number,
  payment: any,
  redeemType: string,
): Promise<any> {
  const unspent = await regtestUtils.faucetComplex(payment.output, amount);
  const utx = await regtestUtils.fetch(unspent.txId);
  // an input is spent against the whole previous transaction
  const nonWitnessUtxo = Buffer.from(utx.txHex, 'hex');
  const mixin: any = {};
  if (redeemType === 'p2sh') mixin.redeemScript = payment.redeem.output;
  return {
    hash: unspent.txId,
    index: unspent.vout,
    nonWitnessUtxo,
    ...mixin,
  };
}
