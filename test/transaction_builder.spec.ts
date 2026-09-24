import * as assert from 'assert';
import { beforeEach, describe, it } from 'mocha';
import {
  ECPair,
  ECPairInterface,
  networks as NETWORKS,
  Transaction,
  TransactionBuilder,
} from '..';
import * as baddress from '../src/address';
import { reverseBuffer } from '../src/bufferutils';
import * as payments from '../src/payments';
import * as bscript from '../src/script';

console.warn = (): void => {
  return;
}; // Silence the Deprecation Warning

import * as fixtures from './fixtures/transaction_builder.json';

function constructSign(
  f: any,
  txb: any,
  useOldSignArgs: any,
): TransactionBuilder {
  const network = (NETWORKS as any)[f.network];
  const stages = f.stages && f.stages.concat();

  f.inputs.forEach((input: any, index: number) => {
    if (!input.signs) return;
    input.signs.forEach((sign: any) => {
      const keyPair = ECPair.fromWIF(sign.keyPair, network);
      let redeemScript;

      if (sign.redeemScript) {
        redeemScript = bscript.fromASM(sign.redeemScript);
      }

      if (useOldSignArgs) {
        // DEPRECATED: v6 will remove this interface
        txb.sign(index, keyPair, redeemScript, sign.hashType);
      } else {
        // prevOutScriptType is required, see /ts_src/transaction_builder.ts
        // The PREVOUT_TYPES constant is a Set with all possible values.
        txb.sign({
          prevOutScriptType: sign.prevOutScriptType,
          vin: index,
          keyPair,
          redeemScript,
          hashType: sign.hashType,
        });
      }

      if (sign.stage) {
        const tx = txb.buildIncomplete();
        assert.strictEqual(tx.toHex(), stages.shift());
        txb = TransactionBuilder.fromTransaction(tx, network);
      }
    });
  });

  return txb;
}

function construct(
  f: any,
  dontSign?: any,
  useOldSignArgs?: any,
): TransactionBuilder {
  const network = (NETWORKS as any)[f.network];
  const txb = new TransactionBuilder(network);

  if (Number.isFinite(f.version)) txb.setVersion(f.version);
  if (f.locktime !== undefined) txb.setLockTime(f.locktime);

  f.inputs.forEach((input: any) => {
    let prevTx;
    if (input.txRaw) {
      const constructed = construct(input.txRaw);
      if (input.txRaw.incomplete) prevTx = constructed.buildIncomplete();
      else prevTx = constructed.build();
    } else if (input.txHex) {
      prevTx = Transaction.fromHex(input.txHex);
    } else {
      prevTx = input.txId;
    }

    let prevTxScript;
    if (input.prevTxScript) {
      prevTxScript = bscript.fromASM(input.prevTxScript);
    }

    txb.addInput(prevTx, input.vout, input.sequence, prevTxScript);
  });

  f.outputs.forEach((output: any) => {
    if (output.address) {
      txb.addOutput(output.address, output.value);
    } else {
      txb.addOutput(bscript.fromASM(output.script), output.value);
    }
  });

  if (dontSign) return txb;
  return constructSign(f, txb, useOldSignArgs);
}

// TODO: Remove loop in v6
for (const useOldSignArgs of [false, true]) {
  // Search for "useOldSignArgs"
  // to find the second part of this console.warn replace
  let consoleWarn: any;
  if (useOldSignArgs) {
    consoleWarn = console.warn;
    // Silence console.warn during these tests
    console.warn = (): undefined => undefined;
  }
  describe(`TransactionBuilder: useOldSignArgs === ${useOldSignArgs}`, () => {
    // constants
    const keyPair = ECPair.fromPrivateKey(
      Buffer.from(
        '0000000000000000000000000000000000000000000000000000000000000001',
        'hex',
      ),
    );
    const scripts = [
      '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH',
      '1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP',
    ].map(x => {
      return baddress.toOutputScript(x);
    });
    const txHash = Buffer.from(
      '0e7cea811c0be9f73c0aca591034396e7264473fc25c1ca45195d7417b36cbe2',
      'hex',
    );

    describe('fromTransaction', () => {
      fixtures.valid.build.forEach(f => {
        it('returns TransactionBuilder, with ' + f.description, () => {
          const network = (NETWORKS as any)[f.network || 'prod'];

          const tx = Transaction.fromHex(f.txHex);
          const txb = TransactionBuilder.fromTransaction(tx, network);
          const txAfter = (f as any).incomplete
            ? txb.buildIncomplete()
            : txb.build();

          assert.strictEqual(txAfter.toHex(), f.txHex);
          assert.strictEqual(txb.network, network);
        });
      });

      fixtures.valid.fromTransaction.forEach(f => {
        it('returns TransactionBuilder, with ' + f.description, () => {
          const tx = new Transaction();

          f.inputs.forEach(input => {
            const txHash2 = Buffer.from(input.txId, 'hex').reverse() as Buffer;

            tx.addInput(
              txHash2,
              input.vout,
              undefined,
              bscript.fromASM(input.scriptSig),
            );
          });

          f.outputs.forEach(output => {
            tx.addOutput(bscript.fromASM(output.script), output.value);
          });

          const txb = TransactionBuilder.fromTransaction(tx);
          const txAfter = f.incomplete ? txb.buildIncomplete() : txb.build();

          txAfter.ins.forEach((input, i) => {
            assert.strictEqual(
              bscript.toASM(input.script),
              f.inputs[i].scriptSigAfter,
            );
          });

          txAfter.outs.forEach((output, i) => {
            assert.strictEqual(
              bscript.toASM(output.script),
              f.outputs[i].script,
            );
          });
        });
      });

      fixtures.valid.fromTransactionSequential.forEach(f => {
        it('with ' + f.description, () => {
          const network = (NETWORKS as any)[f.network];
          const tx = Transaction.fromHex(f.txHex);
          const txb = TransactionBuilder.fromTransaction(tx, network);

          tx.ins.forEach((input, i) => {
            assert.strictEqual(
              bscript.toASM(input.script),
              f.inputs[i].scriptSig,
            );
          });

          constructSign(f, txb, useOldSignArgs);
          const txAfter = f.incomplete ? txb.buildIncomplete() : txb.build();

          txAfter.ins.forEach((input, i) => {
            assert.strictEqual(
              bscript.toASM(input.script),
              f.inputs[i].scriptSigAfter,
            );
          });

          assert.strictEqual(txAfter.toHex(), f.txHexAfter);
        });
      });

      it('classifies transaction inputs', () => {
        const tx = Transaction.fromHex(fixtures.valid.classification.hex);
        const txb = TransactionBuilder.fromTransaction(tx);

        (txb as any).__INPUTS.forEach((i: any) => {
          assert.strictEqual(i.prevOutType, 'scripthash');
          assert.strictEqual(i.redeemScriptType, 'multisig');
        });
      });

      fixtures.invalid.fromTransaction.forEach(f => {
        it('throws ' + f.exception, () => {
          const tx = Transaction.fromHex(f.txHex);

          assert.throws(() => {
            TransactionBuilder.fromTransaction(tx);
          }, new RegExp(f.exception));
        });
      });
    });

    describe('addInput', () => {
      let txb: TransactionBuilder;
      beforeEach(() => {
        txb = new TransactionBuilder();
      });

      it('accepts a txHash, index [and sequence number]', () => {
        const vin = txb.addInput(txHash, 1, 54);
        assert.strictEqual(vin, 0);

        const txIn = (txb as any).__TX.ins[0];
        assert.strictEqual(txIn.hash, txHash);
        assert.strictEqual(txIn.index, 1);
        assert.strictEqual(txIn.sequence, 54);
        assert.strictEqual((txb as any).__INPUTS[0].prevOutScript, undefined);
      });

      it('accepts a txHash, index [, sequence number and scriptPubKey]', () => {
        const vin = txb.addInput(txHash, 1, 54, scripts[1]);
        assert.strictEqual(vin, 0);

        const txIn = (txb as any).__TX.ins[0];
        assert.strictEqual(txIn.hash, txHash);
        assert.strictEqual(txIn.index, 1);
        assert.strictEqual(txIn.sequence, 54);
        assert.strictEqual((txb as any).__INPUTS[0].prevOutScript, scripts[1]);
      });

      it('accepts a prevTx, index [and sequence number]', () => {
        const prevTx = new Transaction();
        // a non-empty scriptSig, so that getHash() and getMalFixHash() differ
        prevTx.addInput(Buffer.alloc(32, 1), 0, undefined, scripts[0]);
        prevTx.addOutput(scripts[0], 0);
        prevTx.addOutput(scripts[1], 1);

        const vin = txb.addInput(prevTx, 1, 54);
        assert.strictEqual(vin, 0);

        const txIn = (txb as any).__TX.ins[0];
        // the outpoint refers to the Tapyrus txid, which omits the scriptSig
        assert.notDeepStrictEqual(prevTx.getMalFixHash(), prevTx.getHash());
        assert.deepStrictEqual(txIn.hash, prevTx.getMalFixHash());
        assert.strictEqual(
          reverseBuffer(Buffer.from(txIn.hash)).toString('hex'),
          prevTx.getId(),
        );
        assert.strictEqual(txIn.index, 1);
        assert.strictEqual(txIn.sequence, 54);
        assert.strictEqual((txb as any).__INPUTS[0].prevOutScript, scripts[1]);
      });

      it('returns the input index', () => {
        assert.strictEqual(txb.addInput(txHash, 0), 0);
        assert.strictEqual(txb.addInput(txHash, 1), 1);
      });

      it('throws if SIGHASH_ALL has been used to sign any existing scriptSigs', () => {
        txb.addInput(txHash, 0);
        txb.addOutput(scripts[0], 1000);
        txb.sign({
          prevOutScriptType: 'p2pkh',
          vin: 0,
          keyPair,
        });

        assert.throws(() => {
          txb.addInput(txHash, 0);
        }, /No, this would invalidate signatures/);
      });
    });

    describe('addOutput', () => {
      let txb: TransactionBuilder;
      beforeEach(() => {
        txb = new TransactionBuilder();
      });

      it('accepts an address string and value', () => {
        const { address } = payments.p2pkh({ pubkey: keyPair.publicKey });
        const vout = txb.addOutput(address!, 1000);
        assert.strictEqual(vout, 0);

        const txout = (txb as any).__TX.outs[0];
        assert.deepStrictEqual(txout.script, scripts[0]);
        assert.strictEqual(txout.value, 1000);
      });

      it('accepts a ScriptPubKey and value', () => {
        const vout = txb.addOutput(scripts[0], 1000);
        assert.strictEqual(vout, 0);

        const txout = (txb as any).__TX.outs[0];
        assert.deepStrictEqual(txout.script, scripts[0]);
        assert.strictEqual(txout.value, 1000);
      });

      it('throws if address is of the wrong network', () => {
        assert.throws(() => {
          txb.addOutput('2NGHjvjw83pcVFgMcA7QvSMh2c246rxLVz9', 1000);
        }, /2NGHjvjw83pcVFgMcA7QvSMh2c246rxLVz9 has no matching Script/);
      });

      it('add second output after signed first input with SIGHASH_NONE', () => {
        txb.addInput(txHash, 0);
        txb.addOutput(scripts[0], 2000);
        txb.sign({
          prevOutScriptType: 'p2pkh',
          vin: 0,
          keyPair,
          hashType: Transaction.SIGHASH_NONE,
        });
        assert.strictEqual(txb.addOutput(scripts[1], 9000), 1);
      });

      it('add first output after signed first input with SIGHASH_NONE', () => {
        txb.addInput(txHash, 0);
        txb.sign({
          prevOutScriptType: 'p2pkh',
          vin: 0,
          keyPair,
          hashType: Transaction.SIGHASH_NONE,
        });
        assert.strictEqual(txb.addOutput(scripts[0], 2000), 0);
      });

      it('add second output after signed first input with SIGHASH_SINGLE', () => {
        txb.addInput(txHash, 0);
        txb.addOutput(scripts[0], 2000);
        txb.sign({
          prevOutScriptType: 'p2pkh',
          vin: 0,
          keyPair,
          hashType: Transaction.SIGHASH_SINGLE,
        });
        assert.strictEqual(txb.addOutput(scripts[1], 9000), 1);
      });

      it('add first output after signed first input with SIGHASH_SINGLE', () => {
        txb.addInput(txHash, 0);
        txb.sign({
          prevOutScriptType: 'p2pkh',
          vin: 0,
          keyPair,
          hashType: Transaction.SIGHASH_SINGLE,
        });
        assert.throws(() => {
          txb.addOutput(scripts[0], 2000);
        }, /No, this would invalidate signatures/);
      });

      it('throws if SIGHASH_ALL has been used to sign any existing scriptSigs', () => {
        txb.addInput(txHash, 0);
        txb.addOutput(scripts[0], 2000);
        txb.sign({
          prevOutScriptType: 'p2pkh',
          vin: 0,
          keyPair,
        });

        assert.throws(() => {
          txb.addOutput(scripts[1], 9000);
        }, /No, this would invalidate signatures/);
      });
    });

    describe('setLockTime', () => {
      it('throws if if there exist any scriptSigs', () => {
        const txb = new TransactionBuilder();
        txb.addInput(txHash, 0);
        txb.addOutput(scripts[0], 100);
        txb.sign({
          prevOutScriptType: 'p2pkh',
          vin: 0,
          keyPair,
        });

        assert.throws(() => {
          txb.setLockTime(65535);
        }, /No, this would invalidate signatures/);
      });
    });

    describe('sign', () => {
      it('supports the alternative abstract interface { publicKey, sign }', () => {
        const innerKeyPair = {
          publicKey: ECPair.makeRandom({
            rng: (): Buffer => {
              return Buffer.alloc(32, 1);
            },
          }).publicKey,
          sign: (): Buffer => {
            return Buffer.alloc(64, 0x5f);
          },
        };

        const txb = new TransactionBuilder();
        txb.setVersion(1);
        txb.addInput(
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
          1,
        );
        txb.addOutput('1111111111111111111114oLvT2', 100000);
        txb.sign({
          prevOutScriptType: 'p2pkh',
          vin: 0,
          keyPair: innerKeyPair,
        });
        assert.strictEqual(
          txb.build().toHex(),
          '0100000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
            'ffffffff010000006a47304402205f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f' +
            '5f5f5f5f5f5f5f5f5f5f5f5f5f02205f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f' +
            '5f5f5f5f5f5f5f5f5f5f5f5f5f5f0121031b84c5567b126440995d3ed5aaba0565' +
            'd71e1834604819ff9c17f5e9d5dd078fffffffff01a0860100000000001976a914' +
            '000000000000000000000000000000000000000088ac00000000',
        );
      });

      it('supports low R signature signing', () => {
        let txb = new TransactionBuilder();
        txb.setVersion(1);
        txb.addInput(
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
          1,
        );
        txb.addOutput('1111111111111111111114oLvT2', 100000);
        txb.sign({
          prevOutScriptType: 'p2pkh',
          vin: 0,
          keyPair,
        });
        // high R
        assert.strictEqual(
          txb.build().toHex(),
          '0100000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
            'ffffffff010000006b483045022100b872677f35c9c14ad9c41d83649fb049250f' +
            '32574e0b2547d67e209ed14ff05d022059b36ad058be54e887a1a311d5c393cb49' +
            '41f6b93a0b090845ec67094de8972b01210279be667ef9dcbbac55a06295ce870b' +
            '07029bfcdb2dce28d959f2815b16f81798ffffffff01a0860100000000001976a9' +
            '14000000000000000000000000000000000000000088ac00000000',
        );

        txb = new TransactionBuilder();
        txb.setVersion(1);
        txb.addInput(
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
          1,
        );
        txb.addOutput('1111111111111111111114oLvT2', 100000);
        txb.setLowR();
        txb.sign({
          prevOutScriptType: 'p2pkh',
          vin: 0,
          keyPair,
        });
        // low R
        assert.strictEqual(
          txb.build().toHex(),
          '0100000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
            'ffffffff010000006a473044022012a601efa8756ebe83e9ac7a7db061c3147e3b' +
            '49d8be67685799fe51a4c8c62f02204d568d301d5ce14af390d566d4fd50e7b8ee' +
            '48e71ec67786c029e721194dae3601210279be667ef9dcbbac55a06295ce870b07' +
            '029bfcdb2dce28d959f2815b16f81798ffffffff01a0860100000000001976a914' +
            '000000000000000000000000000000000000000088ac00000000',
        );
      });

      it('fails when missing required arguments', () => {
        const txb = new TransactionBuilder();
        txb.setVersion(1);
        txb.addInput(
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
          1,
        );
        txb.addOutput('1111111111111111111114oLvT2', 100000);
        assert.throws(() => {
          (txb as any).sign();
        }, /TransactionBuilder sign first arg must be TxbSignArg or number/);
        assert.throws(() => {
          txb.sign({
            prevOutScriptType: 'p2pkh',
            vin: 1,
            keyPair,
          });
        }, /No input at index: 1/);
        assert.throws(() => {
          (txb as any).sign({
            prevOutScriptType: 'p2pkh',
            keyPair,
          });
        }, /sign must include vin parameter as Number \(input index\)/);
        assert.throws(() => {
          (txb as any).sign({
            prevOutScriptType: 'p2pkh',
            vin: 0,
            keyPair: {},
          });
        }, /sign must include keyPair parameter as Signer interface/);
        assert.throws(() => {
          (txb as any).sign({
            prevOutScriptType: 'p2pkh',
            vin: 0,
            keyPair,
            hashType: 'string',
          });
        }, /sign hashType parameter must be a number/);
        if (useOldSignArgs) {
          assert.throws(() => {
            txb.sign(0);
          }, /sign requires keypair/);
        }
      });

      fixtures.invalid.sign.forEach(f => {
        it(
          'throws ' +
            f.exception +
            (f.description ? ' (' + f.description + ')' : ''),
          () => {
            const txb = construct(f, true);

            let threw = false;
            (f.inputs as any).forEach(
              (input: any, index: number): void => {
                input.signs.forEach((sign: any) => {
                  const keyPairNetwork = (NETWORKS as any)[
                    sign.network || f.network
                  ];
                  const keyPair2 = ECPair.fromWIF(sign.keyPair, keyPairNetwork);
                  let redeemScript: Buffer | undefined;

                  if (sign.redeemScript) {
                    redeemScript = bscript.fromASM(sign.redeemScript);
                  }

                  if (sign.throws) {
                    assert.throws(() => {
                      txb.sign({
                        prevOutScriptType: sign.prevOutScriptType,
                        vin: index,
                        keyPair: keyPair2,
                        redeemScript,
                        hashType: sign.hashType,
                      });
                    }, new RegExp(f.exception));
                    threw = true;
                  } else {
                    txb.sign({
                      prevOutScriptType: sign.prevOutScriptType,
                      vin: index,
                      keyPair: keyPair2,
                      redeemScript,
                      hashType: sign.hashType,
                    });
                  }
                });
              },
            );

            assert.strictEqual(threw, true);
          },
        );
      });
    });

    describe('build', () => {
      fixtures.valid.build.forEach(f => {
        it('builds "' + f.description + '"', () => {
          const txb = construct(f, undefined, useOldSignArgs);
          const tx = (f as any).incomplete
            ? txb.buildIncomplete()
            : txb.build();

          assert.strictEqual(tx.toHex(), f.txHex);
        });
      });

      // TODO: remove duplicate test code
      fixtures.invalid.build.forEach(f => {
        describe('for ' + (f.description || f.exception), () => {
          it('throws ' + f.exception, () => {
            assert.throws(() => {
              let txb;
              if (f.txHex) {
                txb = TransactionBuilder.fromTransaction(
                  Transaction.fromHex(f.txHex),
                );
              } else {
                txb = construct(f, undefined, useOldSignArgs);
              }

              txb.build();
            }, new RegExp(f.exception));
          });

          // if throws on incomplete too, enforce that
          if (f.incomplete) {
            it('throws ' + f.exception, () => {
              assert.throws(() => {
                let txb;
                if (f.txHex) {
                  txb = TransactionBuilder.fromTransaction(
                    Transaction.fromHex(f.txHex),
                  );
                } else {
                  txb = construct(f, undefined, useOldSignArgs);
                }

                txb.buildIncomplete();
              }, new RegExp(f.exception));
            });
          } else {
            it('does not throw if buildIncomplete', () => {
              let txb;
              if (f.txHex) {
                txb = TransactionBuilder.fromTransaction(
                  Transaction.fromHex(f.txHex),
                );
              } else {
                txb = construct(f, undefined, useOldSignArgs);
              }

              txb.buildIncomplete();
            });
          }
        });
      });

      it('for incomplete with 0 signatures', () => {
        const randomTxData =
          '010000000100010000000000000000000000000000000000000000000000000000' +
          '000000000000000000ffffffff01e8030000000000001976a9144c9c3dfac4207d' +
          '5d8cb89df5722cb3d712385e3f88ac00000000';
        const randomAddress = '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH';

        const randomTx = Transaction.fromHex(randomTxData);
        const txb = new TransactionBuilder();
        txb.addInput(randomTx, 0);
        txb.addOutput(randomAddress, 1000);
        const tx = txb.buildIncomplete();
        assert(tx);
      });

      it('for incomplete P2SH with 0 signatures', () => {
        const inp = Buffer.from(
          '010000000173120703f67318aef51f7251272a6816d3f7523bb25e34b136d80be9' +
            '59391c100000000000ffffffff0100c817a80400000017a91471a8ec07ff69c6c4' +
            'fee489184c462a9b1b9237488700000000',
          'hex',
        ); // arbitrary P2SH input
        const inpTx = Transaction.fromBuffer(inp);

        const txb = new TransactionBuilder(NETWORKS.dev);
        txb.addInput(inpTx, 0);
        txb.addOutput('2NAkqp5xffoomp5RLBcakuGpZ12GU4twdz4', 1e8); // arbitrary output

        txb.buildIncomplete();
      });
    });

    describe('multisig', () => {
      fixtures.valid.multisig.forEach(f => {
        it(f.description, () => {
          const network = (NETWORKS as any)[f.network];
          let txb = construct(f, true);
          let tx: Transaction;

          f.inputs.forEach((input, i) => {
            const redeemScript = bscript.fromASM(input.redeemScript);

            input.signs.forEach(sign => {
              // rebuild the transaction each-time after the first
              if (tx) {
                // manually override the scriptSig?
                if (sign.scriptSigBefore) {
                  tx.ins[i].script = bscript.fromASM(sign.scriptSigBefore);
                }

                // rebuild
                txb = TransactionBuilder.fromTransaction(tx, network);
              }

              const keyPair2 = ECPair.fromWIF(sign.keyPair, network);
              txb.sign({
                prevOutScriptType: sign.prevOutScriptType,
                vin: i,
                keyPair: keyPair2,
                redeemScript,
                hashType: (sign as any).hashType,
              });

              // update the tx
              tx = txb.buildIncomplete();

              // now verify the serialized scriptSig is as expected
              assert.strictEqual(
                bscript.toASM(tx.ins[i].script),
                sign.scriptSig,
              );
            });
          });

          tx = txb.build();
          assert.strictEqual(tx.toHex(), f.txHex);
        });
      });
    });

    describe('various edge case', () => {
      const network = NETWORKS.dev;

      const edgeKey = ECPair.fromPrivateKey(Buffer.alloc(32, 0x01), {
        network,
      });
      const edgeColorId = Buffer.concat([
        Buffer.from([0xc1]),
        Buffer.alloc(32, 0x11),
      ]);
      const edgeP2pkh = payments.p2pkh({
        pubkey: edgeKey.publicKey,
        network,
      });

      function prevTxWith(
        outs: Array<{ script: Buffer; value: number }>,
      ): Transaction {
        const tx = new Transaction();
        tx.addInput(Buffer.alloc(32, 0x09), 0);
        outs.forEach(o => tx.addOutput(o.script, o.value));
        return tx;
      }

      // the deprecated positional form takes no prevOutScriptType, so these
      // exercise whichever API this pass is for
      function edgeSign(
        txb: TransactionBuilder,
        vin: number,
        signer: ECPairInterface,
        prevOutScriptType: string,
        redeemScript?: Buffer,
      ): void {
        if (useOldSignArgs) txb.sign(vin, signer, redeemScript);
        else
          txb.sign({ prevOutScriptType, vin, keyPair: signer, redeemScript });
      }

      it('signs a cp2sh input when the prevOutScript is known', () => {
        const redeem = payments.p2pkh({
          pubkey: edgeKey.publicKey,
          network,
        });
        const cp2sh = payments.cp2sh({
          redeem,
          colorId: edgeColorId,
          network,
        });
        const prevTx = prevTxWith([{ script: cp2sh.output!, value: 100 }]);

        const txb = new TransactionBuilder(network);
        txb.setVersion(1);
        txb.addInput(prevTx, 0);
        txb.addOutput(cp2sh.output!, 100);
        edgeSign(txb, 0, edgeKey, 'cp2sh', redeem.output);

        const tx = txb.build();
        const sig = bscript.decompile(tx.ins[0].script)![0] as Buffer;
        const decoded = bscript.signature.decode(sig);
        const hash = tx.hashForSignature(0, redeem.output!, decoded.hashType);

        assert.strictEqual(edgeKey.verify(hash, decoded.signature), true);
      });

      // checkSignArgs only runs for the object form, so this one is not
      // parameterised over useOldSignArgs
      it('refuses to sign a coloured input restored from a transaction', () => {
        const cp2pkh = payments.cp2pkh({
          pubkey: edgeKey.publicKey,
          colorId: edgeColorId,
          network,
        });
        const prevTx = prevTxWith([{ script: cp2pkh.output!, value: 100 }]);

        const signed = new TransactionBuilder(network);
        signed.setVersion(1);
        signed.addInput(prevTx, 0);
        signed.addOutput(cp2pkh.output!, 100);
        signed.sign({ prevOutScriptType: 'cp2pkh', vin: 0, keyPair: edgeKey });

        const restored = TransactionBuilder.fromTransaction(
          signed.build(),
          network,
        );

        assert.throws(() => {
          restored.sign({
            prevOutScriptType: 'cp2pkh',
            vin: 0,
            keyPair: edgeKey,
          });
        }, new RegExp('previous output script is a guess'));
      });

      it('signs a cp2sh multisig input without the prevOutScript', () => {
        const other = ECPair.fromPrivateKey(Buffer.alloc(32, 0x02), {
          network,
        });
        const redeem = payments.p2ms({
          m: 2,
          pubkeys: [edgeKey.publicKey, other.publicKey],
          network,
        });
        const cp2sh = payments.cp2sh({
          redeem,
          colorId: edgeColorId,
          network,
        });
        const prevTx = prevTxWith([{ script: cp2sh.output!, value: 100 }]);
        const txid = reverseBuffer(
          Buffer.from(prevTx.getMalFixHash()),
        ).toString('hex');

        // the colour is only in the output being spent, which is not given here
        const txb = new TransactionBuilder(network);
        txb.setVersion(1);
        txb.addInput(txid, 0);
        txb.addOutput(cp2sh.output!, 100);
        edgeSign(txb, 0, edgeKey, 'cp2sh', redeem.output);
        edgeSign(txb, 0, other, 'cp2sh', redeem.output);

        const tx = txb.build();
        const chunks = bscript.decompile(tx.ins[0].script)!;
        const hash = tx.hashForSignature(
          0,
          redeem.output!,
          Transaction.SIGHASH_ALL,
        );

        assert.strictEqual(chunks.length, 4); // OP_0, two signatures, redeem
        assert.ok((chunks[3] as Buffer).equals(redeem.output!));
        for (const key of [edgeKey, other]) {
          const signed = [chunks[1], chunks[2]].some(c => {
            const decoded = bscript.signature.decode(c as Buffer);
            return key.verify(hash, decoded.signature);
          });
          assert.strictEqual(signed, true);
        }
      });

      it('does not count coloured amounts as fees', () => {
        const cp2pkh = payments.cp2pkh({
          pubkey: edgeKey.publicKey,
          colorId: edgeColorId,
          network,
        });
        // 10,000,000 tokens plus 10,000 TPC in, 9,000 TPC out:
        // the real fee is 1,000 and the tokens are burnt
        const prevTx = prevTxWith([
          { script: cp2pkh.output!, value: 10000000 },
          { script: edgeP2pkh.output!, value: 10000 },
        ]);

        const txb = new TransactionBuilder(network);
        txb.setVersion(1);
        txb.addInput(prevTx, 0);
        txb.addInput(prevTx, 1);
        txb.addOutput(edgeP2pkh.output!, 9000);
        edgeSign(txb, 0, edgeKey, 'cp2pkh');
        edgeSign(txb, 1, edgeKey, 'p2pkh');

        assert.doesNotThrow(() => txb.build());
      });

      it('detects an absurd fee above 2^32 satoshi', () => {
        const prevTx = prevTxWith([
          { script: edgeP2pkh.output!, value: 4295167296 },
        ]);

        const txb = new TransactionBuilder(network);
        txb.setVersion(1);
        txb.addInput(prevTx, 0);
        txb.addOutput(edgeP2pkh.output!, 1000);
        edgeSign(txb, 0, edgeKey, 'p2pkh');

        assert.throws(() => {
          txb.build();
        }, new RegExp('Transaction has absurd fees'));
      });

      it('should handle badly pre-filled OP_0s', () => {
        // OP_0 is used where a signature is missing
        const redeemScripSig = bscript.fromASM(
          'OP_0 OP_0 3045022100daf0f4f3339d9fbab42b098045c1e4958ee3b308f4ae17' +
            'be80b63808558d0adb02202f07e3d1f79dc8da285ae0d7f68083d769c11f5621eb' +
            'd9691d6b48c0d4283d7d01 52410479be667ef9dcbbac55a06295ce870b07029bf' +
            'cdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b44' +
            '8a68554199c47d08ffb10d4b84104c6047f9441ed7d6d3045406e95c07cd85c778' +
            'e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f6326' +
            '53266d0e1236431a950cfe52a4104f9308a019258c31049344f85f89d5229b531c' +
            '845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99' +
            '934c2231b6cb9fd7584b8e67253ae',
        );
        const redeemScript = bscript.fromASM(
          'OP_2 0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f' +
            '81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d' +
            '4b8 04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c70' +
            '9ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe5' +
            '2a 04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce03' +
            '6f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e67' +
            '2 OP_3 OP_CHECKMULTISIG',
        );

        const tx = new Transaction();
        tx.addInput(
          Buffer.from(
            'cff58855426469d0ef16442ee9c644c4fb13832467bcbc3173168a7916f07149',
            'hex',
          ),
          0,
          undefined,
          redeemScripSig,
        );
        tx.addOutput(
          Buffer.from(
            '76a914aa4d7985c57e011a8b3dd8e0e5a73aaef41629c588ac',
            'hex',
          ),
          1000,
        );

        // now import the Transaction
        const txb = TransactionBuilder.fromTransaction(tx, NETWORKS.dev);

        const keyPair2 = ECPair.fromWIF(
          '91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgx3cTMqe',
          network,
        );
        txb.sign({
          prevOutScriptType: 'p2sh-p2ms',
          vin: 0,
          keyPair: keyPair2,
          redeemScript,
        });

        const tx2 = txb.build();
        assert.strictEqual(
          tx2.getId(),
          '20e1da734964d555fa1babaa87a291435c0dfba113dfa8ced08f15112a7043af',
        );
        assert.strictEqual(
          bscript.toASM(tx2.ins[0].script),
          'OP_0 3045022100daf0f4f3339d9fbab42b098045c1e4958ee3b308f4ae17be80b' +
            '63808558d0adb02202f07e3d1f79dc8da285ae0d7f68083d769c11f5621ebd9691' +
            'd6b48c0d4283d7d01 3045022100a346c61738304eac5e7702188764d19cdf68f4' +
            '466196729db096d6c87ce18cdd022018c0e8ad03054b0e7e235cda6bedecf35881' +
            'd7aa7d94ff425a8ace7220f38af001 52410479be667ef9dcbbac55a06295ce870' +
            'b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a' +
            '8fd17b448a68554199c47d08ffb10d4b84104c6047f9441ed7d6d3045406e95c07' +
            'cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceae' +
            'ef7f632653266d0e1236431a950cfe52a4104f9308a019258c31049344f85f89d5' +
            '229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f35' +
            '66500a99934c2231b6cb9fd7584b8e67253ae',
        );
      });

      it('should not classify blank scripts as nonstandard', () => {
        let txb = new TransactionBuilder();
        txb.setVersion(1);
        txb.addInput(
          'aa94ab02c182214f090e99a0d57021caffd0f195a81c24602b1028b130b63e31',
          0,
        );

        const incomplete = txb.buildIncomplete().toHex();
        const innerKeyPair = ECPair.fromWIF(
          'L1uyy5qTuGrVXrmrsvHWHgVzW9kKdrp27wBC7Vs6nZDTF2BRUVwy',
        );

        // sign, as expected
        txb.addOutput('1Gokm82v6DmtwKEB8AiVhm82hyFSsEvBDK', 15000);
        txb.sign({
          prevOutScriptType: 'p2pkh',
          vin: 0,
          keyPair: innerKeyPair,
        });
        const txId = txb.build().getId();
        assert.strictEqual(
          txId,
          '5d9060aed4535d1fc88b264d16b15a02183b4a7069822ecfb93d36cdf52b1c43',
        );

        // and, repeat
        txb = TransactionBuilder.fromTransaction(
          Transaction.fromHex(incomplete),
        );
        txb.addOutput('1Gokm82v6DmtwKEB8AiVhm82hyFSsEvBDK', 15000);
        txb.sign({
          prevOutScriptType: 'p2pkh',
          vin: 0,
          keyPair: innerKeyPair,
        });
        const txId2 = txb.build().getId();
        assert.strictEqual(txId, txId2);
        // TODO: Remove me in v6
        if (useOldSignArgs) {
          console.warn = consoleWarn;
        }
      });
    });
  });
}
