import * as assert from 'assert';
import { describe, it } from 'mocha';
import {
  bip32,
  crypto as bcrypto,
  ECPair,
  networks as NETWORKS,
  opcodes,
  payments,
  Pstt,
  registerScriptSigBuilder,
  schnorr,
  script as bscript,
  Transaction,
  unregisterScriptSigBuilder,
} from '..';
import { decode, encode, PsttRecord } from '../src/pstt/container';
import {
  decodeDerivationPath,
  encodeDerivationPath,
} from '../src/pstt/converter';
import { GlobalTypes, InputTypes, OutputTypes } from '../src/pstt/fields';

interface InvalidVector {
  id: string;
  description: string;
  pstt: string;
  expected: { valid: boolean; stage: string; reason: string };
}

interface Intermediate {
  input: number;
  pubkey: string;
  sighash_type: number;
  script_code: string;
  sighash: string;
  signature: string;
}

interface Stage {
  name: string;
  pstt: string;
  identification_txid?: string;
  tx_modifiable?: number;
}

interface ValidSeries {
  id: string;
  description: string;
  intermediates?: Intermediate[];
  stages: Stage[];
  extracted_tx?: string;
  final_txid?: string;
}

const invalidFixtures: InvalidVector[] = require('./fixtures/pstt/invalid.json');
const validFixtures: ValidSeries[] = require('./fixtures/pstt/valid.json');

/**
 * Every record of a PSTT, as an order-independent representation. Two PSTTs
 * with the same record set carry exactly the same information, whatever order
 * their maps were written in.
 */
function recordSet(buffer: Buffer): string[][] {
  const serialize = (records: PsttRecord[]): string[] =>
    records
      .map(
        r =>
          `${r.type.toString(16)}:${r.keydata.toString(
            'hex',
          )}:${r.value.toString('hex')}`,
      )
      .sort();

  const raw = decode(buffer);
  return [
    serialize(raw.global),
    ...raw.inputs.map(serialize),
    ...raw.outputs.map(serialize),
  ];
}

function lastSignedStage(series: ValidSeries): Pstt {
  let signed: Pstt | undefined;
  for (const stage of series.stages) {
    const pstt = Pstt.fromBase64(stage.pstt);
    if (pstt.inputs.some(input => input.partialSig.length > 0)) signed = pstt;
  }
  if (!signed) throw new Error(`${series.id} has no signed stage`);
  return signed;
}

// Key material of the fixtures: SHA256("TIP-174 test vectors") at
// m/44'/2377'/0'/0/i on the dev network.
const root = bip32.fromSeed(
  bcrypto.sha256(Buffer.from('TIP-174 test vectors', 'ascii')),
  NETWORKS.dev,
);

function keyPair(i: number): any {
  const node = root.derivePath(`m/44'/2377'/0'/0/${i}`);
  return ECPair.fromPrivateKey(Buffer.from(node.privateKey!), {
    network: NETWORKS.dev,
  });
}

function p2pkhScript(i: number): Buffer {
  return payments.p2pkh({
    pubkey: keyPair(i).publicKey,
    network: NETWORKS.dev,
  }).output!;
}

function fundingTx(marker: number, value: number, script: Buffer): Transaction {
  const tx = new Transaction();
  tx.version = 1;
  tx.addInput(Buffer.alloc(32, marker), 0);
  tx.addOutput(script, value);
  return tx;
}

function internalTxid(tx: Transaction): Buffer {
  return Buffer.from(tx.getId(), 'hex').reverse();
}

describe('Pstt', () => {
  describe('invalid vectors', () => {
    const parsed = invalidFixtures.filter(v => v.expected.stage === 'rule');

    for (const vector of invalidFixtures.filter(
      v => v.expected.stage === 'parse',
    )) {
      it(`rejects ${vector.id} when parsing`, () => {
        assert.throws(() => Pstt.fromBase64(vector.pstt));
      });
    }

    const ruleChecks: { [id: string]: (pstt: Pstt) => void } = {
      'utxo-txid-mismatch': (pstt): void =>
        assert.throws(
          () => pstt.getPrevOutput(0),
          /does not match PSTT_IN_PREVIOUS_TXID/,
        ),
      'contradictory-locktimes': (pstt): void =>
        assert.throws(() => pstt.locktime, /No locktime kind is acceptable/),
      'single-without-corresponding-output': (pstt): void => {
        const index = pstt.inputs.findIndex(
          input => input.partialSig.length > 0,
        );
        assert.ok(index >= pstt.outputs.length);
        assert.throws(
          () => pstt.hashForSignature(index, Transaction.SIGHASH_SINGLE),
          /must not be signed with SIGHASH_SINGLE/,
        );
        // The digest of such an input degenerates to a constant that commits to
        // nothing, so the verifying side must refuse it too, not only the
        // signing side.
        assert.throws(
          () => pstt.validateSignaturesOfInput(index),
          /must not be signed with SIGHASH_SINGLE/,
        );
      },
      'redeem-script-hash-mismatch': (pstt): void =>
        assert.throws(
          () => pstt.getScriptCode(0),
          /does not hash to the value committed/,
        ),
    };

    for (const vector of parsed) {
      it(`parses ${vector.id} but detects the rule violation`, () => {
        const pstt = Pstt.fromBase64(vector.pstt);
        const check = ruleChecks[vector.id];
        assert.ok(check, `no rule check for ${vector.id}`);
        check(pstt);
      });
    }

    it('covers every rule-stage vector', () => {
      assert.deepStrictEqual(
        parsed.map(v => v.id).sort(),
        Object.keys(ruleChecks).sort(),
      );
    });
  });

  for (const series of validFixtures) {
    describe(`valid vector ${series.id}`, () => {
      it('parses every stage and re-serializes every record', () => {
        for (const stage of series.stages) {
          const buffer = Buffer.from(stage.pstt, 'base64');
          const pstt = Pstt.fromBuffer(buffer);
          assert.deepStrictEqual(
            recordSet(pstt.toBuffer()),
            recordSet(buffer),
            `${series.id}/${stage.name}`,
          );
        }
      });

      it('re-serializes every stage to the bytes it was parsed from', () => {
        // TIP-0174 prescribes no record order, and these vectors are not in the
        // order this library generates records in, so a byte-identical round
        // trip only holds because the parsed order is carried through.
        for (const stage of series.stages) {
          const buffer = Buffer.from(stage.pstt, 'base64');
          assert.strictEqual(
            Pstt.fromBuffer(buffer)
              .toBuffer()
              .toString('hex'),
            buffer.toString('hex'),
            `${series.id}/${stage.name}`,
          );
        }
      });

      it('computes the identification txid and the modifiable flags', () => {
        for (const stage of series.stages) {
          const pstt = Pstt.fromBase64(stage.pstt);
          if (stage.identification_txid)
            assert.strictEqual(
              pstt.getId(),
              stage.identification_txid,
              `${series.id}/${stage.name}`,
            );
          if (stage.tx_modifiable !== undefined)
            assert.strictEqual(
              pstt.global.txModifiable,
              stage.tx_modifiable,
              `${series.id}/${stage.name}`,
            );
        }
      });

      if (series.intermediates) {
        it('recomputes the script code, the sighash and the signatures', () => {
          const pstt = lastSignedStage(series);
          for (const intermediate of series.intermediates!) {
            const label = `${series.id}/input ${intermediate.input}`;
            assert.strictEqual(
              pstt.getScriptCode(intermediate.input).toString('hex'),
              intermediate.script_code,
              `${label} script code`,
            );
            assert.strictEqual(
              pstt
                .hashForSignature(intermediate.input, intermediate.sighash_type)
                .toString('hex'),
              intermediate.sighash,
              `${label} sighash`,
            );

            const pubkey = Buffer.from(intermediate.pubkey, 'hex');
            const partialSig = pstt.inputs[intermediate.input].partialSig.find(
              sig => sig.pubkey.equals(pubkey),
            );
            assert.ok(partialSig, `${label} has a partial signature`);
            assert.strictEqual(
              partialSig!.signature.toString('hex'),
              intermediate.signature,
              `${label} signature`,
            );
            assert.strictEqual(
              pstt.validateSignaturesOfInput(intermediate.input, pubkey),
              true,
              `${label} signature verifies`,
            );
          }
        });
      }

      if (series.extracted_tx) {
        it('extracts the final transaction', () => {
          const finalized = Pstt.fromBase64(
            series.stages[series.stages.length - 1].pstt,
          );
          const tx = finalized.extractTransaction();
          assert.strictEqual(tx.toHex(), series.extracted_tx);
          assert.strictEqual(tx.getId(), series.final_txid);
        });
      }
    });
  }

  describe('Constructor', () => {
    const interactive = validFixtures.find(
      s => s.id === 'fee-provider-interactive',
    )!;
    const userConstructed = interactive.stages[0].pstt;
    const providerConstructed = interactive.stages[1].pstt;

    it('adds an input while the Inputs Modifiable flag is set', () => {
      const pstt = Pstt.fromBase64(userConstructed);
      assert.strictEqual(pstt.isInputsModifiable(), true);
      pstt.addInput({ previousTxid: Buffer.alloc(32, 0x01), outputIndex: 0 });
      assert.strictEqual(pstt.inputs.length, 2);
      // The identification txid changes when an input is added.
      assert.notStrictEqual(
        pstt.getId(),
        interactive.stages[0].identification_txid,
      );
    });

    it('refuses to add an input once construction is finished', () => {
      const pstt = Pstt.fromBase64(providerConstructed);
      assert.strictEqual(pstt.isInputsModifiable(), false);
      assert.throws(
        () =>
          pstt.addInput({
            previousTxid: Buffer.alloc(32, 0x01),
            outputIndex: 0,
          }),
        /Inputs Modifiable flag is not set/,
      );
    });

    it('refuses to add an output once construction is finished', () => {
      const pstt = Pstt.fromBase64(providerConstructed);
      assert.throws(
        () => pstt.addOutput({ amount: 1, script: p2pkhScript(1) }),
        /Outputs Modifiable flag is not set/,
      );
    });
  });

  describe('Updater', () => {
    it('refuses to change the sequence number of a signed input', () => {
      const noninteractive = validFixtures.find(
        s => s.id === 'fee-provider-noninteractive',
      )!;
      const pstt = Pstt.fromBase64(
        noninteractive.stages.find(s => s.name === 'provider-signed')!.pstt,
      );
      assert.throws(
        () => pstt.updateInput(0, { sequence: 0xfffffffe }),
        /is signed/,
      );
    });

    it('refuses to change a sequence number once an input is finalized', () => {
      const series = validFixtures.find(s => s.id === 'p2pkh-ecdsa')!;
      const finalized = series.stages[series.stages.length - 1];
      const pstt = Pstt.fromBase64(finalized.pstt);
      const extracted = pstt.extractTransaction().toHex();

      // finalizeInput drops the PSTT_IN_PARTIAL_SIG records, so a guard that
      // only looked at them would let the sequence number of an input whose
      // signature is already baked into its scriptSig be changed.
      assert.throws(
        () => pstt.updateInput(0, { sequence: 0xfffffffe }),
        /is signed/,
      );
      assert.strictEqual(pstt.extractTransaction().toHex(), extracted);
    });

    it('refuses to change the sequence number of any input while another is finalized', () => {
      const funding0 = fundingTx(0xa6, 100000, p2pkhScript(0));
      const funding1 = fundingTx(0xa7, 100000, p2pkhScript(1));
      const pstt = new Pstt({ network: NETWORKS.dev })
        .addInput({
          previousTxid: internalTxid(funding0),
          outputIndex: 0,
          utxo: funding0.toBuffer(),
        })
        .addInput({
          previousTxid: internalTxid(funding1),
          outputIndex: 0,
          utxo: funding1.toBuffer(),
        })
        .addOutput({ amount: 199000, script: p2pkhScript(2) });

      pstt.signInput(0, keyPair(0));
      pstt.finalizeInput(0);

      // The sighash type of the finalized signature is no longer readable as a
      // record, so it is no longer decidable whether it commits to input #1's
      // sequence number. The conservative answer is the only safe one.
      assert.throws(
        () => pstt.updateInput(1, { sequence: 0xfffffffe }),
        /finalized input carries signatures/,
      );
      assert.strictEqual(pstt.inputs[1].sequence, undefined);
    });

    it('refuses to relax PSTT_GLOBAL_TX_MODIFIABLE once the PSTT is signed', () => {
      const funding = fundingTx(0xa8, 100000, p2pkhScript(0));
      const pstt = new Pstt({ network: NETWORKS.dev })
        .addInput({
          previousTxid: internalTxid(funding),
          outputIndex: 0,
          utxo: funding.toBuffer(),
        })
        .addOutput({ amount: 99000, script: p2pkhScript(1) });
      pstt.signInput(0, keyPair(0));

      // Signing with SIGHASH_ALL cleared both flags. Setting them again would
      // re-open the modification the signature just closed, and every guard of
      // the Constructor and the Input Finalizer consults this field alone.
      assert.strictEqual(pstt.isInputsModifiable(), false);
      assert.strictEqual(pstt.isOutputsModifiable(), false);
      for (const update of [{ txModifiable: 0x01 }, { txModifiable: 0x03 }]) {
        assert.throws(
          () => pstt.updateGlobal(update),
          /Relaxing PSTT_GLOBAL_TX_MODIFIABLE/,
        );
      }
      assert.throws(
        () => pstt.setInputsModifiable(true),
        /Relaxing PSTT_GLOBAL_TX_MODIFIABLE/,
      );
      assert.throws(
        () => pstt.setOutputsModifiable(true),
        /Relaxing PSTT_GLOBAL_TX_MODIFIABLE/,
      );
      assert.strictEqual(pstt.isInputsModifiable(), false);
      assert.throws(() =>
        pstt.addOutput({ amount: 1, script: p2pkhScript(2) }),
      );
      assert.strictEqual(pstt.validateSignaturesOfInput(0), true);
    });

    it('refuses to clear the Has SIGHASH_SINGLE flag a Signer set', () => {
      const funding = fundingTx(0xa9, 100000, p2pkhScript(0));
      const pstt = new Pstt({ network: NETWORKS.dev })
        .addInput({
          previousTxid: internalTxid(funding),
          outputIndex: 0,
          utxo: funding.toBuffer(),
        })
        .addOutput({ amount: 99000, script: p2pkhScript(1) });
      pstt.signInput(0, keyPair(0), {
        sighashType:
          Transaction.SIGHASH_SINGLE | Transaction.SIGHASH_ANYONECANPAY,
      });

      assert.strictEqual(pstt.hasSighashSingle(), true);
      // Clearing it would drop the pairing rule that keeps every input at the
      // position of the output its signature covers.
      assert.throws(
        () => pstt.updateGlobal({ txModifiable: 0x01 }),
        /Relaxing PSTT_GLOBAL_TX_MODIFIABLE/,
      );
      assert.strictEqual(pstt.hasSighashSingle(), true);
    });

    it('allows tightening PSTT_GLOBAL_TX_MODIFIABLE on a signed PSTT', () => {
      const funding = fundingTx(0xaa, 100000, p2pkhScript(0));
      const pstt = new Pstt({ network: NETWORKS.dev })
        .addInput({
          previousTxid: internalTxid(funding),
          outputIndex: 0,
          utxo: funding.toBuffer(),
        })
        .addOutput({ amount: 99000, script: p2pkhScript(1) });
      pstt.signInput(0, keyPair(0), {
        sighashType: Transaction.SIGHASH_NONE,
      });

      // SIGHASH_NONE leaves the outputs modifiable; declaring construction
      // finished is a tightening, so it stays allowed.
      assert.strictEqual(pstt.isOutputsModifiable(), true);
      pstt.finishConstruction();
      assert.strictEqual(pstt.isOutputsModifiable(), false);
    });

    it('allows changing an unsigned input while only SIGHASH_ANYONECANPAY signatures exist', () => {
      const noninteractive = validFixtures.find(
        s => s.id === 'fee-provider-noninteractive',
      )!;
      const pstt = Pstt.fromBase64(
        noninteractive.stages.find(s => s.name === 'provider-added-input')!
          .pstt,
      );
      pstt.updateInput(1, { sequence: 0xfffffffe });
      assert.strictEqual(pstt.inputs[1].sequence, 0xfffffffe);
    });

    it('refuses to change any sequence number while a SIGHASH_ALL signature exists', () => {
      const funding0 = fundingTx(0xa1, 100000, p2pkhScript(0));
      const funding1 = fundingTx(0xa2, 100000, p2pkhScript(1));
      const pstt = new Pstt({ network: NETWORKS.dev })
        .addInput({
          previousTxid: internalTxid(funding0),
          outputIndex: 0,
          utxo: funding0.toBuffer(),
        })
        .addInput({
          previousTxid: internalTxid(funding1),
          outputIndex: 0,
          utxo: funding1.toBuffer(),
        })
        .addOutput({ amount: 199000, script: p2pkhScript(2) });

      pstt.signInput(0, keyPair(0));
      assert.throws(
        () => pstt.updateInput(1, { sequence: 0xfffffffe }),
        /SIGHASH_ALL signature commits to the sequence number/,
      );
    });

    it('refuses to change a required locktime once the PSTT is signed', () => {
      const funding = fundingTx(0xa3, 100000, p2pkhScript(0));
      const pstt = new Pstt({ network: NETWORKS.dev })
        .addInput({
          previousTxid: internalTxid(funding),
          outputIndex: 0,
          utxo: funding.toBuffer(),
        })
        .addOutput({ amount: 99000, script: p2pkhScript(1) });
      pstt.signInput(0, keyPair(0));

      // Every signature commits to the locktime, so an Updater must not move it.
      assert.throws(
        () => pstt.updateInput(0, { requiredHeightLocktime: 680000 }),
        /would change the locktime/,
      );
      assert.throws(
        () => pstt.updateInput(0, { requiredTimeLocktime: 1700000000 }),
        /would change the locktime/,
      );
      assert.strictEqual(pstt.locktime, 0);
      assert.strictEqual(pstt.validateSignaturesOfInput(0), true);
    });

    it('refuses to move the locktime or the features of a signed PSTT', () => {
      const funding = fundingTx(0xa5, 100000, p2pkhScript(0));
      const pstt = new Pstt({ network: NETWORKS.dev })
        .addInput({
          previousTxid: internalTxid(funding),
          outputIndex: 0,
          utxo: funding.toBuffer(),
        })
        .addOutput({ amount: 99000, script: p2pkhScript(1) });
      pstt.signInput(0, keyPair(0));

      // The signature hash covers both, so the global map is as closed to an
      // Updater as the required locktime fields of an input are.
      assert.throws(
        () => pstt.updateGlobal({ fallbackLocktime: 500 }),
        /would change the locktime/,
      );
      assert.throws(
        () => pstt.setFallbackLocktime(500),
        /would change the locktime/,
      );
      assert.throws(() => pstt.setFeatures(2), /would invalidate them/);
      assert.throws(
        () => pstt.updateGlobal({ partialSig: [] } as any),
        /An Updater must not set/,
      );

      assert.strictEqual(pstt.locktime, 0);
      assert.strictEqual(pstt.global.features, 1);
      assert.strictEqual(pstt.validateSignaturesOfInput(0), true);
    });

    it('refuses to touch the fields of the Signer and the Input Finalizer', () => {
      const funding = fundingTx(0xa4, 100000, p2pkhScript(0));
      const pstt = new Pstt({ network: NETWORKS.dev })
        .addInput({
          previousTxid: internalTxid(funding),
          outputIndex: 0,
          utxo: funding.toBuffer(),
        })
        .addOutput({ amount: 99000, script: p2pkhScript(1) });
      pstt.signInput(0, keyPair(0));

      const forbidden: object[] = [
        { partialSig: [] },
        { finalScriptSig: Buffer.alloc(1) },
        { previousTxid: Buffer.alloc(32) },
        { outputIndex: 3 },
      ];
      for (const update of forbidden) {
        assert.throws(
          () => pstt.updateInput(0, update as any),
          /An Updater must not set/,
        );
      }
      assert.strictEqual(pstt.inputs[0].partialSig.length, 1);

      for (const update of [{ amount: 1 }, { script: p2pkhScript(2) }]) {
        assert.throws(
          () => pstt.updateOutput(0, update as any),
          /An Updater must not set/,
        );
      }
      assert.strictEqual(pstt.outputs[0].amount, 99000);
    });
  });

  describe('Combiner', () => {
    const multisig = validFixtures.find(
      s => s.id === 'cp2sh-multisig-combine',
    )!;
    const stage = (name: string): string =>
      multisig.stages.find(s => s.name === name)!.pstt;

    it('merges two independently signed PSTTs, keeping unknown records', () => {
      const combined = Pstt.fromBase64(stage('signed-a')).combine(
        Pstt.fromBase64(stage('signed-b')),
      );
      assert.deepStrictEqual(
        recordSet(combined.toBuffer()),
        recordSet(Buffer.from(stage('combined'), 'base64')),
      );
    });

    it('does not resurrect a flag the other copy cleared when it signed', () => {
      const noninteractive = validFixtures.find(
        s => s.id === 'fee-provider-noninteractive',
      )!;
      const stageOf = (name: string): string =>
        noninteractive.stages.find(s => s.name === name)!.pstt;

      // Two copies of one PSTT: one still accepting the fee input, one where
      // the provider's SIGHASH_ALL signature closed the input list.
      const mine = Pstt.fromBase64(stageOf('provider-added-input'));
      const theirs = Pstt.fromBase64(stageOf('provider-signed'));
      assert.strictEqual(mine.isInputsModifiable(), true);
      assert.strictEqual(theirs.isInputsModifiable(), false);

      mine.combine(theirs);

      // Keeping this copy's value would leave a PSTT that carries a
      // SIGHASH_ALL signature and still invites another input.
      assert.strictEqual(mine.isInputsModifiable(), false);
      assert.throws(
        () =>
          mine.addInput({
            previousTxid: Buffer.alloc(32, 0x01),
            outputIndex: 0,
          }),
        /Inputs Modifiable flag is not set/,
      );
    });

    it('refuses PSTTs with different identifiers', () => {
      const other = validFixtures.find(s => s.id === 'p2pkh-ecdsa')!;
      assert.throws(
        () =>
          Pstt.fromBase64(stage('signed-a')).combine(
            Pstt.fromBase64(other.stages[0].pstt),
          ),
        /different identifiers/,
      );
    });

    const signedWithSequence = (marker: number, sequence?: number): Pstt => {
      const funding = fundingTx(marker, 100000, p2pkhScript(0));
      const pstt = new Pstt({ network: NETWORKS.dev })
        .addInput({
          previousTxid: internalTxid(funding),
          outputIndex: 0,
          utxo: funding.toBuffer(),
          sequence,
        })
        .addOutput({ amount: 99000, script: p2pkhScript(1) });
      return pstt.signInput(0, keyPair(0));
    };

    it('refuses PSTTs whose sequence numbers disagree', () => {
      // The identifier is computed with every sequence number set to 0, so two
      // copies that disagree about one still identify as the same PSTT.
      // Merging would keep this copy's value and silently invalidate the
      // other's SIGHASH_ALL signature, which commits to the other one.
      const mine = signedWithSequence(0xab);
      const theirs = signedWithSequence(0xab, 0xfffffffe);
      assert.strictEqual(theirs.getId(), mine.getId());
      assert.strictEqual(theirs.validateSignaturesOfInput(0), true);

      assert.throws(
        () => mine.combine(theirs),
        /Input #0 has a different sequence number/,
      );
      assert.strictEqual(mine.inputs[0].sequence, undefined);
    });

    it('combines copies that agree on an explicit sequence number', () => {
      const mine = signedWithSequence(0xac, 0xfffffffe);
      const theirs = signedWithSequence(0xac, 0xfffffffe);

      mine.combine(theirs);
      assert.strictEqual(mine.inputs[0].sequence, 0xfffffffe);
      assert.strictEqual(mine.validateSignaturesOfInput(0), true);
    });
  });

  describe('Input Finalizer', () => {
    it('refuses to finalize a modifiable PSTT', () => {
      const interactive = validFixtures.find(
        s => s.id === 'fee-provider-interactive',
      )!;
      const pstt = Pstt.fromBase64(interactive.stages[0].pstt);
      assert.throws(
        () => pstt.finalizeAllInputs(),
        /must not be finalized while it is still modifiable/,
      );
    });

    it('drops the signature collection records and keeps the rest', () => {
      const series = validFixtures.find(
        s => s.id === 'cp2sh-multisig-combine',
      )!;
      const pstt = Pstt.fromBase64(
        series.stages.find(s => s.name === 'combined')!.pstt,
      );
      const unknown = pstt.inputs[0].unknownKeyVals.map(r => r.type);

      pstt.finalizeAllInputs();

      assert.deepStrictEqual(pstt.inputs[0].partialSig, []);
      assert.deepStrictEqual(pstt.inputs[0].bip32Derivation, []);
      assert.strictEqual(pstt.inputs[0].sighashType, undefined);
      assert.strictEqual(pstt.inputs[0].redeemScript, undefined);
      assert.ok(pstt.inputs[0].utxo);
      assert.deepStrictEqual(
        pstt.inputs[0].unknownKeyVals.map(r => r.type),
        unknown,
      );
      assert.deepStrictEqual(
        recordSet(pstt.toBuffer()),
        recordSet(
          Buffer.from(
            series.stages.find(s => s.name === 'finalized')!.pstt,
            'base64',
          ),
        ),
      );
    });

    it('reports a second finalization instead of a missing signature', () => {
      const series = validFixtures.find(
        s => s.id === 'cp2sh-multisig-combine',
      )!;
      const pstt = Pstt.fromBase64(
        series.stages.find(s => s.name === 'combined')!.pstt,
      );
      pstt.finalizeAllInputs();
      const scriptSig = pstt.inputs[0].finalScriptSig!;

      assert.throws(() => pstt.finalizeInput(0), /is already finalized/);
      // finalizeAllInputs stays idempotent: it skips what is already done.
      pstt.finalizeAllInputs();
      assert.ok(pstt.inputs[0].finalScriptSig!.equals(scriptSig));
    });
  });

  describe('end to end', () => {
    const workflow = (id: string, scheme: 'ecdsa' | 'schnorr'): void => {
      it(`reproduces the ${id} series from scratch`, () => {
        const series = validFixtures.find(s => s.id === id)!;
        const outputs =
          series.id === 'p2pkh-ecdsa' ? [60000, 39000] : [55000, 44500];
        const funding = fundingTx(0xaa, 100000, p2pkhScript(0));

        const pstt = new Pstt({ network: NETWORKS.dev })
          .addInput({
            previousTxid: internalTxid(funding),
            outputIndex: 0,
            utxo: funding.toBuffer(),
            sighashType: Transaction.SIGHASH_ALL,
          })
          .addOutput({ amount: outputs[0], script: p2pkhScript(1) })
          .addOutput({ amount: outputs[1], script: p2pkhScript(2) });

        assert.strictEqual(pstt.getId(), series.stages[0].identification_txid);

        pstt.signInput(0, keyPair(0), { scheme });
        assert.strictEqual(
          pstt.inputs[0].partialSig[0].signature.toString('hex'),
          series.intermediates![0].signature,
        );
        assert.strictEqual(pstt.validateSignaturesOfAllInputs(), true);

        pstt.finalizeAllInputs();
        const tx = pstt.extractTransaction();
        assert.strictEqual(tx.toHex(), series.extracted_tx);
        assert.strictEqual(tx.getId(), series.final_txid);
      });
    };

    workflow('p2pkh-ecdsa', 'ecdsa');
    workflow('p2pkh-schnorr', 'schnorr');

    it('round-trips through base64 and hex', () => {
      const source = validFixtures[0].stages[1].pstt;
      const pstt = Pstt.fromBase64(source);
      assert.deepStrictEqual(
        recordSet(Pstt.fromHex(pstt.toHex()).toBuffer()),
        recordSet(Buffer.from(source, 'base64')),
      );
    });
  });

  describe('container', () => {
    it('round-trips a value that needs a 3-byte compact size', () => {
      const pstt = Pstt.fromBuffer(
        encode({
          global: globalRecords([
            { type: 0xf0, keydata: EMPTY, value: Buffer.alloc(300, 0x11) },
          ]),
          inputs: [],
          outputs: [],
        }),
      );
      assert.strictEqual(pstt.global.unknownKeyVals[0].value.length, 300);
      assert.deepStrictEqual(
        recordSet(Pstt.fromBuffer(pstt.toBuffer()).toBuffer()),
        recordSet(pstt.toBuffer()),
      );
    });

    it('round-trips a value that needs a 5-byte compact size', () => {
      const pstt = Pstt.fromBuffer(
        encode({
          global: globalRecords([
            { type: 0xf0, keydata: EMPTY, value: Buffer.alloc(70000, 0x22) },
          ]),
          inputs: [],
          outputs: [],
        }),
      );
      assert.strictEqual(pstt.global.unknownKeyVals[0].value.length, 70000);
    });

    it('rejects a non-minimal 3-byte compact size', () => {
      assert.throws(
        () =>
          Pstt.fromBuffer(withKeyLengthPrefix(Buffer.from([0xfd, 0x02, 0x00]))),
        /not minimally encoded/,
      );
    });

    it('rejects a non-minimal 5-byte compact size', () => {
      assert.throws(
        () =>
          Pstt.fromBuffer(
            withKeyLengthPrefix(Buffer.from([0xfe, 0x02, 0x00, 0x00, 0x00])),
          ),
        /not minimally encoded/,
      );
    });

    it('rejects a non-minimal 9-byte compact size', () => {
      assert.throws(
        () =>
          Pstt.fromBuffer(
            withKeyLengthPrefix(Buffer.from([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0])),
          ),
        /not minimally encoded/,
      );
    });

    it('rejects a truncated PSTT', () => {
      const buffer = Buffer.from(validFixtures[0].stages[0].pstt, 'base64');
      assert.throws(
        () => Pstt.fromBuffer(buffer.slice(0, buffer.length - 4)),
        /truncated|not terminated/,
      );
    });

    it('rejects a keytype that overruns the declared key length', () => {
      // keylen = 1, but the minimally encoded keytype 0x0100 takes 3 bytes.
      const buffer = Buffer.concat([
        MAGIC_BYTES,
        Buffer.from([0x01, 0xfd, 0x00, 0x01, 0x00, 0x00]),
      ]);
      assert.throws(
        () => Pstt.fromBuffer(buffer),
        /keytype exceeds the declared key length/,
      );
    });

    it('rejects a count field with trailing data', () => {
      const buffer = encode({
        global: [
          { type: GlobalTypes.TX_FEATURES, keydata: EMPTY, value: FEATURES },
          {
            type: GlobalTypes.INPUT_COUNT,
            keydata: EMPTY,
            value: Buffer.from([0x00, 0x00]),
          },
          {
            type: GlobalTypes.OUTPUT_COUNT,
            keydata: EMPTY,
            value: Buffer.from([0x00]),
          },
        ],
        inputs: [],
        outputs: [],
      });
      assert.throws(() => Pstt.fromBuffer(buffer), /has trailing data/);
    });
  });

  describe('field conversion', () => {
    it('encodes and decodes a derivation path', () => {
      const fingerprint = Buffer.from('deadbeef', 'hex');
      const value = encodeDerivationPath(fingerprint, "m/44'/2377'/0'/0/7");
      assert.deepStrictEqual(decodeDerivationPath(value, 'test'), {
        masterFingerprint: fingerprint,
        path: "m/44'/2377'/0'/0/7",
      });
    });

    it('accepts the h form of a hardened element', () => {
      const fingerprint = Buffer.alloc(4);
      assert.ok(
        encodeDerivationPath(fingerprint, 'm/44h/0h').equals(
          encodeDerivationPath(fingerprint, "m/44'/0'"),
        ),
      );
    });

    it('rejects a malformed derivation path', () => {
      const fingerprint = Buffer.alloc(4);
      assert.throws(
        () => encodeDerivationPath(fingerprint, "44'/0'"),
        /Invalid derivation path/,
      );
      assert.throws(
        () => encodeDerivationPath(fingerprint, 'm/abc'),
        /Invalid derivation path/,
      );
      assert.throws(
        () => decodeDerivationPath(Buffer.alloc(6), 'test'),
        /fingerprint followed by 32-bit indexes/,
      );
    });

    it('rejects fields whose value has the wrong length', () => {
      const cases: Array<[PsttRecord, RegExp]> = [
        [
          {
            type: GlobalTypes.FALLBACK_LOCKTIME,
            keydata: EMPTY,
            value: Buffer.alloc(3),
          },
          /4-byte value/,
        ],
        [
          {
            type: GlobalTypes.TX_MODIFIABLE,
            keydata: EMPTY,
            value: Buffer.alloc(2),
          },
          /1-byte value/,
        ],
        [
          {
            type: GlobalTypes.XPUB,
            keydata: Buffer.alloc(10),
            value: Buffer.alloc(8),
          },
          /78-byte extended public key/,
        ],
      ];

      for (const [record, message] of cases) {
        assert.throws(
          () =>
            Pstt.fromBuffer(
              encode({
                global: globalRecords([record]),
                inputs: [],
                outputs: [],
              }),
            ),
          message,
        );
      }
    });

    it('rejects PSTT_GLOBAL_TX_MODIFIABLE with a reserved bit set', () => {
      // TIP-0174, Transaction Modifiable Flags: only bits 0-2 are defined and
      // "the remaining bits are reserved and must be set to 0".
      const parse = (value: number): Pstt =>
        Pstt.fromBuffer(
          encode({
            global: globalRecords([
              {
                type: GlobalTypes.TX_MODIFIABLE,
                keydata: EMPTY,
                value: Buffer.from([value]),
              },
            ]),
            inputs: [],
            outputs: [],
          }),
        );

      for (const value of [0x08, 0x80, 0xff]) {
        assert.throws(() => parse(value), /reserves at 0/);
      }
      // Every combination of the defined bits stays acceptable.
      for (let value = 0; value <= 0b111; value++) {
        assert.strictEqual(parse(value).global.txModifiable, value);
      }
    });

    it('rejects an output amount that is not 8 bytes', () => {
      assert.throws(
        () =>
          Pstt.fromBuffer(
            encode({
              global: globalRecords([], 0, 1),
              inputs: [],
              outputs: [
                [
                  {
                    type: OutputTypes.AMOUNT,
                    keydata: EMPTY,
                    value: Buffer.alloc(4),
                  },
                  {
                    type: OutputTypes.SCRIPT,
                    keydata: EMPTY,
                    value: p2pkhScript(0),
                  },
                ],
              ],
            }),
          ),
        /8-byte value/,
      );
    });

    it('rejects the reserved witness and Taproot type values', () => {
      const funding = fundingTx(0xb3, 1000, p2pkhScript(0));
      // Witness UTXO, witness script, finalized scriptWitness,
      // proof-of-reserves, and the Taproot fields of BIP-371.
      for (const type of [0x01, 0x05, 0x08, 0x09, 0x13, 0x16, 0x18]) {
        assert.throws(
          () =>
            Pstt.fromBuffer(
              encode({
                global: globalRecords([], 1, 0),
                inputs: [
                  inputRecords(funding, [
                    { type, keydata: EMPTY, value: Buffer.alloc(4) },
                  ]),
                ],
                outputs: [],
              }),
            ),
          new RegExp(`Reserved input type 0x${type.toString(16)}`),
        );
      }

      // Witness script and the Taproot fields of the output map.
      for (const type of [0x01, 0x05, 0x06, 0x07]) {
        assert.throws(
          () =>
            Pstt.fromBuffer(
              encode({
                global: globalRecords([], 0, 1),
                inputs: [],
                outputs: [
                  [
                    {
                      type: OutputTypes.AMOUNT,
                      keydata: EMPTY,
                      value: Buffer.alloc(8),
                    },
                    {
                      type: OutputTypes.SCRIPT,
                      keydata: EMPTY,
                      value: p2pkhScript(0),
                    },
                    { type, keydata: EMPTY, value: Buffer.alloc(4) },
                  ],
                ],
              }),
            ),
          new RegExp(`Reserved output type 0x${type.toString(16)}`),
        );
      }
    });

    it('rejects an undefined sighash type in PSTT_IN_SIGHASH_TYPE', () => {
      const funding = fundingTx(0xb4, 1000, p2pkhScript(0));
      const withSighashType = (value: number): Buffer => {
        const buffer = Buffer.alloc(4);
        buffer.writeUInt32LE(value, 0);
        return encode({
          global: globalRecords([], 1, 0),
          inputs: [
            inputRecords(funding, [
              {
                type: InputTypes.SIGHASH_TYPE,
                keydata: EMPTY,
                value: buffer,
              },
            ]),
          ],
          outputs: [],
        });
      };

      for (const invalid of [0x00, 0x04, 0x99, 0x100]) {
        assert.throws(
          () => Pstt.fromBuffer(withSighashType(invalid)),
          /Invalid PSTT_IN_SIGHASH_TYPE/,
        );
      }
      // SIGHASH_ALL/NONE/SINGLE, each with and without SIGHASH_ANYONECANPAY.
      for (const valid of [0x01, 0x02, 0x03, 0x81, 0x82, 0x83]) {
        assert.strictEqual(
          Pstt.fromBuffer(withSighashType(valid)).inputs[0].sighashType,
          valid,
        );
      }
    });

    it('rejects a hash preimage keyed by the wrong hash length', () => {
      const funding = fundingTx(0xb1, 1000, p2pkhScript(0));
      assert.throws(
        () =>
          Pstt.fromBuffer(
            encode({
              global: globalRecords([], 1, 0),
              inputs: [
                inputRecords(funding, [
                  {
                    type: InputTypes.SHA256,
                    keydata: Buffer.alloc(20),
                    value: Buffer.from('preimage'),
                  },
                ]),
              ],
              outputs: [],
            }),
          ),
        /must be a 32-byte hash/,
      );
    });

    it('round-trips preimages, xpubs and proprietary records', () => {
      const funding = fundingTx(0xb2, 1000, p2pkhScript(0));
      const pstt = new Pstt({ network: NETWORKS.dev })
        .addInput({
          previousTxid: internalTxid(funding),
          outputIndex: 0,
          utxo: funding.toBuffer(),
          ripemd160Preimages: { ['11'.repeat(20)]: Buffer.from('a') },
          sha256Preimages: { ['22'.repeat(32)]: Buffer.from('b') },
          hash160Preimages: { ['33'.repeat(20)]: Buffer.from('c') },
          hash256Preimages: { ['44'.repeat(32)]: Buffer.from('d') },
          unknownKeyVals: [
            {
              type: InputTypes.PROPRIETARY,
              keydata: Buffer.from('0474617079', 'hex'),
              value: Buffer.from('proprietary'),
            },
          ],
        })
        .addOutput({ amount: 900, script: p2pkhScript(1) });

      pstt.updateGlobal({
        version: 0,
        xpub: [
          {
            extendedPubkey: Buffer.alloc(78, 0x55),
            masterFingerprint: Buffer.from('01020304', 'hex'),
            path: "m/44'/2377'/0'",
          },
        ],
      });
      pstt.updateOutput(0, {
        redeemScript: p2pkhScript(2),
        bip32Derivation: [
          {
            pubkey: keyPair(2).publicKey,
            masterFingerprint: Buffer.from('01020304', 'hex'),
            path: "m/44'/2377'/0'/0/2",
          },
        ],
      });

      const parsed = Pstt.fromBuffer(pstt.toBuffer());
      assert.deepStrictEqual(
        recordSet(parsed.toBuffer()),
        recordSet(pstt.toBuffer()),
      );
      assert.strictEqual(parsed.global.version, 0);
      assert.deepStrictEqual(parsed.global.xpub, pstt.global.xpub);
      assert.deepStrictEqual(
        parsed.inputs[0].sha256Preimages,
        pstt.inputs[0].sha256Preimages,
      );
      assert.deepStrictEqual(
        parsed.inputs[0].unknownKeyVals,
        pstt.inputs[0].unknownKeyVals,
      );
      assert.deepStrictEqual(
        parsed.outputs[0].bip32Derivation,
        pstt.outputs[0].bip32Derivation,
      );
    });
  });

  describe('roles', () => {
    const spendable = (): Pstt => {
      const funding = fundingTx(0xc1, 100000, p2pkhScript(0));
      return new Pstt({ network: NETWORKS.dev })
        .addInput({
          previousTxid: internalTxid(funding),
          outputIndex: 0,
          utxo: funding.toBuffer(),
        })
        .addOutput({ amount: 99000, script: p2pkhScript(1) });
    };

    it('accepts a display-order txid and an address', () => {
      const funding = fundingTx(0xc2, 100000, p2pkhScript(0));
      const pstt = new Pstt({ network: NETWORKS.dev })
        .addInput({ previousTxid: funding.getId(), outputIndex: 0 })
        .addOutput({
          amount: 99000,
          address: payments.p2pkh({
            pubkey: keyPair(1).publicKey,
            network: NETWORKS.dev,
          }).address!,
        });
      assert.ok(pstt.inputs[0].previousTxid.equals(internalTxid(funding)));
      assert.ok(pstt.outputs[0].script.equals(p2pkhScript(1)));
    });

    it('rejects a malformed outpoint and an output without a script', () => {
      const pstt = new Pstt({ network: NETWORKS.dev });
      assert.throws(
        () => pstt.addInput({ previousTxid: Buffer.alloc(31), outputIndex: 0 }),
        /must be 32 bytes/,
      );
      assert.throws(
        () => pstt.addOutput({ amount: 1 }),
        /needs a script or an address/,
      );
    });

    it('sets the features and the fallback locktime', () => {
      const pstt = spendable()
        .setFeatures(1)
        .setFallbackLocktime(500);
      assert.strictEqual(pstt.locktime, 500);
      assert.strictEqual(pstt.getTransaction().version, 1);
    });

    it('resolves the locktime to the highest required height', () => {
      const funding = fundingTx(0xc3, 1000, p2pkhScript(0));
      const pstt = spendable().addInput({
        previousTxid: internalTxid(funding),
        outputIndex: 0,
        requiredHeightLocktime: 680000,
      });
      pstt.addInput({
        previousTxid: internalTxid(funding),
        outputIndex: 1,
        requiredHeightLocktime: 690000,
        requiredTimeLocktime: 1700000000,
      });
      assert.strictEqual(pstt.locktime, 690000);
    });

    it('refuses to add an input that would change the locktime of a signed PSTT', () => {
      const pstt = spendable().setInputsModifiable(true);
      // SIGHASH_ALL|SIGHASH_ANYONECANPAY leaves the Inputs Modifiable flag set.
      pstt.signInput(0, keyPair(0), { sighashType: 0x81 });
      assert.strictEqual(pstt.isInputsModifiable(), true);
      const funding = fundingTx(0xc4, 1000, p2pkhScript(0));
      assert.throws(
        () =>
          pstt.addInput({
            previousTxid: internalTxid(funding),
            outputIndex: 0,
            requiredHeightLocktime: 680000,
          }),
        /would change the locktime/,
      );
    });

    it('refuses to add once a SIGHASH_ALL signature has cleared the flags', () => {
      const pstt = spendable();
      // A PSTT under construction starts modifiable; SIGHASH_ALL clears both.
      assert.strictEqual(pstt.isInputsModifiable(), true);
      assert.strictEqual(pstt.isOutputsModifiable(), true);
      pstt.signInput(0, keyPair(0));
      assert.strictEqual(pstt.global.txModifiable, 0);
      assert.throws(
        () => pstt.addOutput({ amount: 1, script: p2pkhScript(1) }),
        /Outputs Modifiable flag is not set/,
      );
      assert.throws(
        () =>
          pstt.addInput({
            previousTxid: Buffer.alloc(32, 0x01),
            outputIndex: 0,
          }),
        /Inputs Modifiable flag is not set/,
      );
    });

    it('treats a parsed PSTT without PSTT_GLOBAL_TX_MODIFIABLE as fixed', () => {
      // TIP-0174: "If the field is omitted, the transaction is not modifiable."
      const created = validFixtures.find(s => s.id === 'p2pkh-ecdsa')!
        .stages[0];
      const pstt = Pstt.fromBase64(created.pstt);
      assert.strictEqual(pstt.global.txModifiable, undefined);
      assert.throws(
        () => pstt.addOutput({ amount: 1, script: p2pkhScript(1) }),
        /Outputs Modifiable flag is not set/,
      );
      assert.throws(
        () =>
          pstt.addInput({
            previousTxid: Buffer.alloc(32, 0x01),
            outputIndex: 0,
          }),
        /Inputs Modifiable flag is not set/,
      );
      // Round-tripping must not invent the record it never carried.
      assert.deepStrictEqual(
        recordSet(pstt.toBuffer()),
        recordSet(Buffer.from(created.pstt, 'base64')),
      );
    });

    it('sets the Has SIGHASH_SINGLE flag when signing with SIGHASH_SINGLE', () => {
      const pstt = spendable().setInputsModifiable(true);
      // SIGHASH_SINGLE|SIGHASH_ANYONECANPAY keeps the inputs modifiable.
      pstt.signInput(0, keyPair(0), { sighashType: 0x83 });
      assert.strictEqual(pstt.hasSighashSingle(), true);
      assert.strictEqual(pstt.isInputsModifiable(), true);
      assert.strictEqual(pstt.isOutputsModifiable(), false);
      assert.throws(
        () =>
          pstt.addInput({
            previousTxid: Buffer.alloc(32, 0x01),
            outputIndex: 0,
          }),
        /use addInputOutputPair/,
      );
    });

    it('adds an input and an output as a pair while the Has SIGHASH_SINGLE flag is set', () => {
      const pstt = spendable();
      pstt.updateGlobal({ txModifiable: 0b111 });

      assert.throws(
        () => pstt.addOutput({ amount: 1, script: p2pkhScript(1) }),
        /use addInputOutputPair/,
      );
      pstt.addInputOutputPair(
        { previousTxid: Buffer.alloc(32, 0x01), outputIndex: 0 },
        { amount: 1, script: p2pkhScript(2) },
      );
      assert.strictEqual(pstt.inputs.length, 2);
      assert.strictEqual(pstt.outputs.length, 2);
    });

    it('pairs an addition even when the outputs already outnumber the inputs', () => {
      // Appending never moves an existing input or output, so the positional
      // correspondence a SIGHASH_SINGLE signature relies on is preserved.
      const pstt = spendable().addOutput({
        amount: 1,
        script: p2pkhScript(2),
      });
      pstt.updateGlobal({ txModifiable: 0b111 });
      assert.strictEqual(pstt.inputs.length, 1);
      assert.strictEqual(pstt.outputs.length, 2);

      pstt.addInputOutputPair(
        { previousTxid: Buffer.alloc(32, 0x02), outputIndex: 0 },
        { amount: 1, script: p2pkhScript(3) },
      );
      assert.strictEqual(pstt.inputs.length, 2);
      assert.strictEqual(pstt.outputs.length, 3);
    });

    it('refuses a pair whose input would have no corresponding output', () => {
      const funding = fundingTx(0xc9, 1000, p2pkhScript(0));
      const pstt = spendable();
      pstt.updateGlobal({ txModifiable: 0b011 });
      pstt.addInput({ previousTxid: internalTxid(funding), outputIndex: 0 });
      pstt.updateGlobal({ txModifiable: 0b111 });
      assert.strictEqual(pstt.inputs.length, 2);
      assert.strictEqual(pstt.outputs.length, 1);

      assert.throws(
        () =>
          pstt.addInputOutputPair(
            { previousTxid: Buffer.alloc(32, 0x02), outputIndex: 0 },
            { amount: 1, script: p2pkhScript(2) },
          ),
        /no corresponding output/,
      );
    });

    it('clears the modifiable flags when construction is finished', () => {
      const pstt = spendable()
        .setInputsModifiable(true)
        .setOutputsModifiable(true)
        .finishConstruction();
      assert.strictEqual(pstt.global.txModifiable, 0);
      assert.strictEqual(pstt.isOutputsModifiable(), false);
    });

    it('refuses to set a reserved bit of PSTT_GLOBAL_TX_MODIFIABLE', () => {
      const pstt = spendable();
      const before = pstt.global.txModifiable;
      // 0x100 does not fit in the single byte the field holds, so it would be
      // truncated to 0 on serialization rather than stored.
      for (const value of [0x08, 0x80, 0xff, 0x100]) {
        assert.throws(
          () => pstt.updateGlobal({ txModifiable: value }),
          /reserves at 0/,
        );
      }
      assert.strictEqual(pstt.global.txModifiable, before);
      // The defined bits are still settable through the same path.
      pstt.updateGlobal({ txModifiable: 0b111 });
      assert.strictEqual(pstt.global.txModifiable, 0b111);
    });

    it('refuses to touch a flag while a reserved bit is set', () => {
      const pstt = spendable();
      // `data` is public, so a caller can reach the field without going
      // through the parser or updateGlobal; the flag setters catch it next.
      pstt.global.txModifiable = 0b1000;
      assert.throws(() => pstt.setInputsModifiable(false), /reserves at 0/);
      assert.throws(() => pstt.setOutputsModifiable(true), /reserves at 0/);
    });

    it('reports a missing input or output', () => {
      const pstt = spendable();
      assert.throws(() => pstt.updateInput(5, {}), /No input #5/);
      assert.throws(() => pstt.updateOutput(5, {}), /No output #5/);
    });

    it('reports a missing or out of range UTXO', () => {
      const funding = fundingTx(0xc5, 1000, p2pkhScript(0));
      const pstt = new Pstt({ network: NETWORKS.dev }).addInput({
        previousTxid: internalTxid(funding),
        outputIndex: 3,
      });
      assert.throws(() => pstt.getPrevOutput(0), /has no PSTT_IN_UTXO record/);
      pstt.updateInput(0, { utxo: funding.toBuffer() });
      assert.throws(() => pstt.getPrevOutput(0), /is out of range/);
    });

    it('requires a redeem script for a P2SH input', () => {
      const redeem = bscript.compile([
        opcodes.OP_2,
        keyPair(3).publicKey,
        keyPair(4).publicKey,
        opcodes.OP_2,
        opcodes.OP_CHECKMULTISIG,
      ]);
      const p2sh = payments.p2sh({
        redeem: { output: redeem },
        network: NETWORKS.dev,
      }).output!;
      const funding = fundingTx(0xc6, 100000, p2sh);
      const pstt = new Pstt({ network: NETWORKS.dev })
        .addInput({
          previousTxid: internalTxid(funding),
          outputIndex: 0,
          utxo: funding.toBuffer(),
        })
        .addOutput({ amount: 99000, script: p2pkhScript(1) })
        .finishConstruction();

      assert.throws(
        () => pstt.getScriptCode(0),
        /has no PSTT_IN_REDEEM_SCRIPT record/,
      );

      pstt.updateInput(0, { redeemScript: redeem });
      assert.ok(pstt.getScriptCode(0).equals(redeem));
      assert.throws(() => pstt.finalizeInput(0), /0 of the 2 signatures/);

      pstt.signInput(0, keyPair(3));
      assert.throws(() => pstt.finalizeInput(0), /1 of the 2 signatures/);

      pstt.signInput(0, keyPair(4));
      assert.strictEqual(pstt.validateSignaturesOfInput(0), true);
      pstt.finalizeAllInputs();

      const chunks = bscript.decompile(pstt.inputs[0].finalScriptSig!)!;
      assert.strictEqual(chunks[0], opcodes.OP_0);
      assert.strictEqual(chunks.length, 4);
      assert.ok((chunks[3] as Buffer).equals(redeem));
      assert.ok(pstt.extractTransaction().ins[0].script.length > 0);
    });

    it('finalizes a P2PK input', () => {
      const p2pk = payments.p2pk({
        pubkey: keyPair(0).publicKey,
        network: NETWORKS.dev,
      }).output!;
      const funding = fundingTx(0xc7, 1000, p2pk);
      const pstt = new Pstt({ network: NETWORKS.dev })
        .addInput({
          previousTxid: internalTxid(funding),
          outputIndex: 0,
          utxo: funding.toBuffer(),
        })
        .addOutput({ amount: 900, script: p2pkhScript(1) });

      pstt.signAllInputs(keyPair(0));
      pstt.finalizeAllInputs();
      assert.strictEqual(pstt.inputs[0].partialSig.length, 0);
      assert.ok(pstt.extractTransaction().ins[0].script.length > 0);
    });

    it('refuses to finalize an unsupported script type', () => {
      const nulldata = payments.embed({ data: [Buffer.from('hello')] }).output!;
      const funding = fundingTx(0xc8, 1000, nulldata);
      const pstt = new Pstt({ network: NETWORKS.dev })
        .addInput({
          previousTxid: internalTxid(funding),
          outputIndex: 0,
          utxo: funding.toBuffer(),
        })
        .addOutput({ amount: 900, script: p2pkhScript(1) })
        .finishConstruction();
      assert.throws(() => pstt.finalizeInput(0), /unsupported script type/);
    });

    it('refuses to mix signature schemes on one input', () => {
      const pstt = spendable();
      pstt.signInput(0, keyPair(0));
      assert.throws(
        () => pstt.signInput(0, keyPair(0), { scheme: 'schnorr' }),
        /already carries a ecdsa signature/,
      );
    });

    it('applies the Signer rules to a signature produced elsewhere', () => {
      const redeem = bscript.compile([
        opcodes.OP_2,
        keyPair(3).publicKey,
        keyPair(4).publicKey,
        opcodes.OP_2,
        opcodes.OP_CHECKMULTISIG,
      ]);
      const p2sh = payments.p2sh({
        redeem: { output: redeem },
        network: NETWORKS.dev,
      }).output!;
      const funding = fundingTx(0xca, 100000, p2sh);
      const pstt = new Pstt({ network: NETWORKS.dev })
        .addInput({
          previousTxid: internalTxid(funding),
          outputIndex: 0,
          utxo: funding.toBuffer(),
          redeemScript: redeem,
        })
        .addOutput({ amount: 99000, script: p2pkhScript(1) });

      pstt.signInput(0, keyPair(3));

      // A 65-byte value is a Schnorr signature to the Tapyrus interpreter, so
      // importing one next to an ECDSA signature would mix the two schemes
      // inside a single OP_CHECKMULTISIG evaluation.
      const hash = pstt.hashForSignature(0, Transaction.SIGHASH_ALL);
      const schnorrSig = Buffer.concat([
        schnorr.sign(keyPair(4).privateKey!, hash),
        Buffer.from([Transaction.SIGHASH_ALL]),
      ]);
      assert.throws(
        () =>
          pstt.addPartialSig(0, {
            pubkey: keyPair(4).publicKey,
            signature: schnorrSig,
          }),
        /already carries a ecdsa signature/,
      );

      // A key of the wrong length would serialize into a PSTT nobody can parse.
      assert.throws(
        () =>
          pstt.addPartialSig(0, {
            pubkey: Buffer.alloc(20, 0x07),
            signature: bscript.signature.encode(
              keyPair(4).sign(hash),
              Transaction.SIGHASH_ALL,
            ),
          }),
        /must be 33 or 65 bytes/,
      );

      assert.strictEqual(pstt.inputs[0].partialSig.length, 1);
      assert.ok(Pstt.fromBuffer(pstt.toBuffer()));
    });

    it('refuses a signature that ignores the requested sighash type', () => {
      const pstt = spendable();
      pstt.updateInput(0, { sighashType: Transaction.SIGHASH_ALL });

      const hash = pstt
        .getTransaction()
        .hashForSignature(0, pstt.getScriptCode(0), Transaction.SIGHASH_NONE);
      assert.throws(
        () =>
          pstt.addPartialSig(0, {
            pubkey: keyPair(0).publicKey,
            signature: bscript.signature.encode(
              keyPair(0).sign(hash),
              Transaction.SIGHASH_NONE,
            ),
          }),
        /requests sighash type 1/,
      );
      assert.strictEqual(pstt.inputs[0].partialSig.length, 0);
    });

    it('refuses a further signature once the input is finalized', () => {
      const pstt = spendable();
      pstt.signInput(0, keyPair(0));
      pstt.finalizeInput(0);

      // The Input Finalizer removed the PSTT_IN_PARTIAL_SIG records, so no
      // role may put one back next to the finalized scriptSig.
      assert.throws(
        () => pstt.signInput(0, keyPair(0)),
        /takes no further signature/,
      );
      assert.throws(
        () =>
          pstt.addPartialSig(0, {
            pubkey: keyPair(0).publicKey,
            signature: Buffer.alloc(71, 0x01),
          }),
        /takes no further signature/,
      );
      assert.deepStrictEqual(pstt.inputs[0].partialSig, []);
    });

    it('refuses to report a signature by an unrelated public key as valid', () => {
      const pstt = spendable();
      const hash = pstt.hashForSignature(0, Transaction.SIGHASH_ALL);

      // A hostile party can key a PSTT_IN_PARTIAL_SIG record with any public
      // key. A signature by a key the script never mentions is valid in
      // itself, yet contributes nothing towards spending the output.
      pstt.inputs[0].partialSig.push({
        pubkey: keyPair(5).publicKey,
        signature: bscript.signature.encode(
          keyPair(5).sign(hash),
          Transaction.SIGHASH_ALL,
        ),
      });
      assert.throws(
        () => pstt.validateSignaturesOfInput(0),
        /can not be satisfied with/,
      );
      assert.throws(
        () => pstt.validateSignaturesOfAllInputs(),
        /can not be satisfied with/,
      );
    });

    it('refuses to validate a SIGHASH_SINGLE signature with no matching output', () => {
      const funding0 = fundingTx(0xcb, 100000, p2pkhScript(0));
      const funding1 = fundingTx(0xcc, 100000, p2pkhScript(1));
      const pstt = new Pstt({ network: NETWORKS.dev })
        .addInput({
          previousTxid: internalTxid(funding0),
          outputIndex: 0,
          utxo: funding0.toBuffer(),
        })
        .addInput({
          previousTxid: internalTxid(funding1),
          outputIndex: 0,
          utxo: funding1.toBuffer(),
        })
        .addOutput({ amount: 190000, script: p2pkhScript(2) });

      // Input #1 has no output #1, so signing it is refused outright.
      assert.throws(
        () =>
          pstt.signInput(1, keyPair(1), {
            sighashType: Transaction.SIGHASH_SINGLE,
          }),
        /must not be signed with SIGHASH_SINGLE/,
      );

      // A hostile party can still put such a signature in a PSTT it sends. The
      // digest is the constant 0x00..01, so the signature verifies against it
      // while committing to nothing; the validator must refuse it regardless.
      const digest = pstt
        .getTransaction()
        .hashForSignature(1, pstt.getScriptCode(1), Transaction.SIGHASH_SINGLE);
      assert.strictEqual(
        digest.toString('hex'),
        '00'.repeat(31) + '01',
        'the degenerate digest of the legacy algorithm',
      );
      pstt.inputs[1].partialSig.push({
        pubkey: keyPair(1).publicKey,
        signature: bscript.signature.encode(
          keyPair(1).sign(digest),
          Transaction.SIGHASH_SINGLE,
        ),
      });

      assert.throws(
        () => pstt.validateSignaturesOfInput(1),
        /must not be signed with SIGHASH_SINGLE/,
      );
    });

    it('finalizes a script type registered by the caller', () => {
      const nulldata = payments.embed({ data: [Buffer.from('hello')] }).output!;
      const funding = fundingTx(0xcd, 1000, nulldata);
      const pstt = new Pstt({ network: NETWORKS.dev })
        .addInput({
          previousTxid: internalTxid(funding),
          outputIndex: 0,
          utxo: funding.toBuffer(),
        })
        .addOutput({ amount: 900, script: p2pkhScript(1) })
        .finishConstruction();

      assert.throws(() => pstt.finalizeInput(0), /unsupported script type/);

      registerScriptSigBuilder('nulldata', () => [opcodes.OP_1]);
      try {
        pstt.finalizeInput(0);
        assert.deepStrictEqual(
          bscript.decompile(pstt.inputs[0].finalScriptSig!),
          [opcodes.OP_1],
        );
      } finally {
        unregisterScriptSigBuilder('nulldata');
      }
    });

    it('uses the sighash type the input requests', () => {
      const pstt = spendable();
      pstt.updateInput(0, { sighashType: Transaction.SIGHASH_NONE });
      assert.throws(
        () => pstt.signInput(0, keyPair(0), { sighashType: 0x81 }),
        /requests sighash type 2/,
      );
      pstt.signInput(0, keyPair(0));
      assert.strictEqual(
        pstt.inputs[0].partialSig[0].signature.slice(-1)[0],
        Transaction.SIGHASH_NONE,
      );
    });

    it('rejects an invalid sighash type', () => {
      assert.throws(
        () => spendable().hashForSignature(0, 0x04),
        /Invalid sighash type/,
      );
    });

    it('signs with an external Schnorr signer', () => {
      const pstt = spendable();
      const inner = keyPair(0);
      pstt.signInput(
        0,
        {
          publicKey: inner.publicKey,
          sign: (hash: Buffer): Buffer => inner.sign(hash),
          signSchnorr: (hash: Buffer): Buffer =>
            require('../src/schnorr').sign(inner.privateKey!, hash),
        },
        { scheme: 'schnorr' },
      );
      assert.strictEqual(pstt.validateSignaturesOfInput(0), true);
    });

    it('rejects a Schnorr request from a signer that can not produce one', () => {
      const inner = keyPair(0);
      assert.throws(
        () =>
          spendable().signInput(
            0,
            {
              publicKey: inner.publicKey,
              sign: (hash: Buffer): Buffer => inner.sign(hash),
            },
            { scheme: 'schnorr' },
          ),
        /can not produce Schnorr signatures/,
      );
    });

    it('reports when a key signs no input', () => {
      assert.throws(
        () => spendable().signAllInputs(keyPair(5)),
        /No inputs were signed/,
      );
    });

    it('reports when there is nothing to validate or finalize', () => {
      const pstt = spendable();
      assert.throws(
        () => pstt.validateSignaturesOfInput(0),
        /No signatures to validate/,
      );
      assert.throws(
        () => pstt.extractTransaction(),
        /has no PSTT_IN_FINAL_SCRIPTSIG record/,
      );

      const empty = new Pstt({ network: NETWORKS.dev });
      assert.throws(() => empty.validateSignaturesOfAllInputs(), /no inputs/);
      assert.throws(() => empty.finalizeAllInputs(), /no inputs/);
    });

    it('detects a tampered signature', () => {
      const pstt = spendable();
      pstt.signInput(0, keyPair(0));
      const signature = Buffer.from(pstt.inputs[0].partialSig[0].signature);
      signature[10] ^= 0xff;
      pstt.inputs[0].partialSig[0].signature = signature;
      assert.strictEqual(pstt.validateSignaturesOfInput(0), false);
    });

    it('knows which inputs a key can sign', () => {
      const pstt = spendable();
      assert.strictEqual(pstt.inputHasPubkey(0, keyPair(0).publicKey), true);
      assert.strictEqual(pstt.inputHasPubkey(0, keyPair(1).publicKey), false);

      const unknownUtxo = new Pstt({ network: NETWORKS.dev }).addInput({
        previousTxid: Buffer.alloc(32, 0x01),
        outputIndex: 0,
      });
      assert.strictEqual(
        unknownUtxo.inputHasPubkey(0, keyPair(0).publicKey),
        false,
      );

      pstt.signInput(0, keyPair(0));
      pstt.finalizeAllInputs();
      assert.strictEqual(pstt.inputHasPubkey(0, keyPair(0).publicKey), false);
    });
  });
});

const EMPTY = Buffer.alloc(0);
const MAGIC_BYTES = Buffer.from('70737474ff', 'hex');
const FEATURES = Buffer.from('01000000', 'hex');

function globalRecords(
  extra: PsttRecord[] = [],
  inputCount: number = 0,
  outputCount: number = 0,
): PsttRecord[] {
  return [
    { type: GlobalTypes.TX_FEATURES, keydata: EMPTY, value: FEATURES },
    {
      type: GlobalTypes.INPUT_COUNT,
      keydata: EMPTY,
      value: Buffer.from([inputCount]),
    },
    {
      type: GlobalTypes.OUTPUT_COUNT,
      keydata: EMPTY,
      value: Buffer.from([outputCount]),
    },
    ...extra,
  ];
}

function inputRecords(
  prevTx: Transaction,
  extra: PsttRecord[] = [],
): PsttRecord[] {
  const outputIndex = Buffer.alloc(4);
  return [
    {
      type: InputTypes.PREVIOUS_TXID,
      keydata: EMPTY,
      value: Buffer.from(prevTx.getId(), 'hex').reverse(),
    },
    { type: InputTypes.OUTPUT_INDEX, keydata: EMPTY, value: outputIndex },
    ...extra,
  ];
}

/**
 * A PSTT whose global map starts with a record whose key length is written
 * with the given compact size bytes, so that the reader hits that encoding.
 */
function withKeyLengthPrefix(compactSize: Buffer): Buffer {
  return Buffer.concat([MAGIC_BYTES, compactSize, Buffer.alloc(8)]);
}
