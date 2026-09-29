import * as assert from 'assert';
import { describe, it } from 'mocha';
import { PaymentCreator } from '../src/payments';
import * as u from './payments.utils';
['cp2pkh', 'cp2sh', 'embed', 'p2ms', 'p2pk', 'p2pkh', 'p2sh'].forEach(p => {
  describe(p, () => {
    let fn: PaymentCreator;
    const payment = require('../src/payments/' + p);
    if (p === 'embed') {
      fn = payment.p2data;
    } else {
      fn = payment[p];
    }
    const fixtures = require('./fixtures/' + p);

    fixtures.valid.forEach((f: any) => {
      it(f.description + ' as expected', () => {
        const args = u.preform(f.arguments);
        const actual = fn(args, f.options);

        u.equate(actual, f.expected, f.arguments);
      });

      it(f.description + ' as expected (no validation)', () => {
        const args = u.preform(f.arguments);
        const actual = fn(
          args,
          Object.assign({}, f.options, {
            validate: false,
          }),
        );

        u.equate(actual, f.expected, f.arguments);
      });
    });

    fixtures.invalid.forEach((f: any) => {
      it(
        'throws ' + f.exception + (f.description ? 'for ' + f.description : ''),
        () => {
          const args = u.preform(f.arguments);

          assert.throws(() => {
            fn(args, f.options);
          }, new RegExp(f.exception));
        },
      );
    });

    if (p === 'cp2pkh' || p === 'cp2sh') {
      const hash = Buffer.from('11'.repeat(20), 'hex');
      const network = require('../src/networks').prod;
      const version =
        p === 'cp2pkh' ? network.coloredPubKeyHash : network.coloredScriptHash;
      const bad = Buffer.from('c4' + '22'.repeat(32), 'hex');
      const address = require('bs58check').encode(
        Buffer.concat([Buffer.from([version]), bad, hash]),
      );
      const output = Buffer.concat([
        Buffer.from([0x21]),
        bad,
        Buffer.from([0xbc]), // OP_COLOR
        p === 'cp2pkh'
          ? Buffer.concat([
              Buffer.from('76a914', 'hex'),
              hash,
              Buffer.from('88ac', 'hex'),
            ])
          : Buffer.concat([
              Buffer.from('a914', 'hex'),
              hash,
              Buffer.from('87', 'hex'),
            ]),
      ]);

      [{ address }, { output }].forEach(args => {
        it(
          'refuses an invalid color from ' +
            Object.keys(args)[0] +
            ' without validation',
          () => {
            assert.throws(() => {
              const built: any = fn(args as any, { validate: false });
              built.colorId;
            }, /color identifier/);
          },
        );
      });
    }

    // cross-verify dynamically too
    if (!fixtures.dynamic) return;
    const { depends, details } = fixtures.dynamic;

    details.forEach((f: any) => {
      const detail = u.preform(f);
      const disabled: any = {};
      if (f.disabled)
        f.disabled.forEach((k: string) => {
          disabled[k] = true;
        });

      for (const key in depends) {
        if (key in disabled) continue;
        const dependencies = depends[key];

        dependencies.forEach((dependency: any) => {
          if (!Array.isArray(dependency)) dependency = [dependency];

          const args = {};
          dependency.forEach((d: any) => {
            u.from(d, detail, args);
          });
          const expected = u.from(key, detail);

          it(
            f.description +
              ', ' +
              key +
              ' derives from ' +
              JSON.stringify(dependency),
            () => {
              u.equate(fn(args), expected);
            },
          );
        });
      }
    });
  });
});
