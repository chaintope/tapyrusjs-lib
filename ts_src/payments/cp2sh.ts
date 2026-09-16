import * as bcrypto from '../crypto';
import { prod as PROD_NETWORK } from '../networks';
import * as bscript from '../script';
import { Payment, PaymentOpts, Stack } from './index';
import * as lazy from './lazy';
import {
  checkHash,
  checkInput,
  checkRedeem,
  chunksFn,
  coloredAddressFn,
  redeemFn,
  validColorId,
} from './util';
const typef = require('typeforce');
const OPS = bscript.OPS;

const bs58check = require('bs58check');

// input: [redeemScriptSig ...] {redeemScript}
// output: {colorId} OP_COLOR OP_HASH160 {hash160(redeemScript)} OP_EQUAL
export function cp2sh(a: Payment, opts?: PaymentOpts): Payment {
  if (!a.address && !a.hash && !a.output && !a.redeem && !a.input)
    throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});

  typef(
    {
      network: typef.maybe(typef.Object),

      address: typef.maybe(typef.String),
      hash: typef.maybe(typef.BufferN(20)),
      output: typef.maybe(typef.BufferN(58)),

      redeem: typef.maybe({
        network: typef.maybe(typef.Object),
        output: typef.maybe(typef.Buffer),
        input: typef.maybe(typef.Buffer),
      }),
      input: typef.maybe(typef.Buffer),
      colorId: typef.maybe(typef.BufferN(33)),
    },
    a,
  );

  let network = a.network;
  if (!network) {
    network = (a.redeem && a.redeem.network) || PROD_NETWORK;
  }

  const o: Payment = { network };

  const _address = coloredAddressFn(a.address!);

  // output dependents
  lazy.prop(o, 'address', () => {
    if (!o.hash) return;
    if (!o.colorId) return;

    const payload = Buffer.allocUnsafe(54);
    payload.writeUInt8(o.network!.coloredScriptHash, 0);
    o.colorId.copy(payload, 1);
    o.hash.copy(payload, 34);
    return bs58check.encode(payload);
  });
  lazy.prop(o, 'hash', () => {
    // in order of least effort
    if (a.output) return a.output.slice(37, 57);
    if (a.address) return _address().hash;
    if (o.redeem && o.redeem.output) return bcrypto.hash160(o.redeem.output);
  });
  lazy.prop(o, 'output', () => {
    if (!o.hash) return;
    if (!o.colorId) return;
    return bscript.compile([
      o.colorId,
      OPS.OP_COLOR,
      OPS.OP_HASH160,
      o.hash,
      OPS.OP_EQUAL,
    ]);
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
    const nameParts = ['cp2sh'];
    if (o.redeem !== undefined && o.redeem.name !== undefined)
      nameParts.push(o.redeem.name!);
    return nameParts.join('-');
  });
  lazy.prop(o, 'colorId', () => {
    if (a.output) return a.output.slice(1, 34);
    if (a.address) return _address().colorId;
  });

  if (opts.validate) {
    let hash: Buffer = Buffer.from([]);
    let colorId: Buffer = Buffer.from([]);
    if (a.address) {
      if (_address().version !== network.coloredScriptHash)
        throw new TypeError('Invalid version or Network mismatch');
      if (_address().hash.length !== 20) throw new TypeError('Invalid address');
      if (_address().colorId.length !== 33)
        throw new TypeError('Invalid address');
      hash = _address().hash;
      colorId = _address().colorId;
    }

    if (a.hash) {
      checkHash(hash, a.hash);
      hash = a.hash;
    }

    if (a.colorId) {
      colorId = validColorId(colorId, a.colorId!);
    }

    if (a.output) {
      if (
        a.output.length !== 58 ||
        a.output[0] !== 0x21 ||
        a.output[34] !== OPS.OP_COLOR ||
        a.output[35] !== OPS.OP_HASH160 ||
        a.output[36] !== 0x14 ||
        a.output[57] !== OPS.OP_EQUAL
      )
        throw new TypeError('Output is invalid');

      const colorId2 = a.output.slice(1, 34);
      validColorId(colorId, colorId2);

      const hash2 = a.output.slice(37, 57);
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
