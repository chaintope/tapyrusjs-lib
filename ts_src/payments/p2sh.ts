import * as bcrypto from '../crypto';
import { prod as PROD_NETWORK } from '../networks';
import * as bscript from '../script';
import { Payment, PaymentOpts, Stack } from './index';
import * as lazy from './lazy';
import {
  addressFn,
  checkHash,
  checkInput,
  checkRedeem,
  chunksFn,
  redeemFn,
} from './util';
const typef = require('typeforce');
const OPS = bscript.OPS;

const bs58check = require('bs58check');

// input: [redeemScriptSig ...] {redeemScript}
// output: OP_HASH160 {hash160(redeemScript)} OP_EQUAL
export function p2sh(a: Payment, opts?: PaymentOpts): Payment {
  if (!a.address && !a.hash && !a.output && !a.redeem && !a.input)
    throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});

  typef(
    {
      network: typef.maybe(typef.Object),

      address: typef.maybe(typef.String),
      hash: typef.maybe(typef.BufferN(20)),
      output: typef.maybe(typef.BufferN(23)),

      redeem: typef.maybe({
        network: typef.maybe(typef.Object),
        output: typef.maybe(typef.Buffer),
        input: typef.maybe(typef.Buffer),
      }),
      input: typef.maybe(typef.Buffer),
    },
    a,
  );

  let network = a.network;
  if (!network) {
    network = (a.redeem && a.redeem.network) || PROD_NETWORK;
  }

  const o: Payment = { network };

  const _address = addressFn(a.address!);

  // output dependents
  lazy.prop(o, 'address', () => {
    if (!o.hash) return;

    const payload = Buffer.allocUnsafe(21);
    payload.writeUInt8(o.network!.scriptHash, 0);
    o.hash.copy(payload, 1);
    return bs58check.encode(payload);
  });
  lazy.prop(o, 'hash', () => {
    // in order of least effort
    if (a.output) return a.output.slice(2, 22);
    if (a.address) return _address().hash;
    if (o.redeem && o.redeem.output) return bcrypto.hash160(o.redeem.output);
  });
  lazy.prop(o, 'output', () => {
    if (!o.hash) return;
    return bscript.compile([OPS.OP_HASH160, o.hash, OPS.OP_EQUAL]);
  });

  // input dependents
  lazy.prop(o, 'redeem', () => {
    if (!a.input) return;
    return redeemFn(a, network)();
  });
  lazy.prop(o, 'input', () => {
    if (!a.redeem || !a.redeem.input || !a.redeem.output) return;
    return bscript.compile(
      ([] as Stack).concat(
        bscript.decompile(a.redeem.input) as Stack,
        a.redeem.output,
      ),
    );
  });
  lazy.prop(o, 'name', () => {
    const nameParts = ['p2sh'];
    if (o.redeem !== undefined && o.redeem.name !== undefined)
      nameParts.push(o.redeem.name!);
    return nameParts.join('-');
  });

  if (opts.validate) {
    let hash: Buffer = Buffer.from([]);
    if (a.address) {
      if (_address().version !== network.scriptHash)
        throw new TypeError('Invalid version or Network mismatch');
      if (_address().hash.length !== 20) throw new TypeError('Invalid address');
      hash = _address().hash;
    }

    if (a.hash) {
      checkHash(hash, a.hash);
      hash = a.hash;
    }

    if (a.output) {
      if (
        a.output.length !== 23 ||
        a.output[0] !== OPS.OP_HASH160 ||
        a.output[1] !== 0x14 ||
        a.output[22] !== OPS.OP_EQUAL
      )
        throw new TypeError('Output is invalid');

      const hash2 = a.output.slice(2, 22);
      checkHash(hash, hash2);
      hash = hash2;
    }

    if (a.input) {
      const hash2 = checkInput(chunksFn(a.input), redeemFn(a, network), hash);
      if (hash2) {
        hash = hash2;
      }
    }

    checkRedeem(a, network, redeemFn(a, network), hash);
  }

  return Object.assign(o, a);
}
