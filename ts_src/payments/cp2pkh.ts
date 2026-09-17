import * as bcrypto from '../crypto';
import { prod as PROD_NETWORK } from '../networks';
import * as bscript from '../script';
import * as types from '../types';
import { Payment, PaymentOpts } from './index';
import * as lazy from './lazy';
import { checkHash, chunksFn, coloredAddressFn, validColorId } from './util';

const typef = require('typeforce');
const OPS = bscript.OPS;
const ecc = require('tiny-secp256k1');

const bs58check = require('bs58check');

// input: {signature} {pubkey}
// output: {colorId} OP_COLOR OP_DUP OP_HASH160 {hash160(pubkey)} OP_EQUALVERIFY OP_CHECKSIG
export function cp2pkh(a: Payment, opts?: PaymentOpts): Payment {
  if (!a.address && !a.hash && !a.output && !a.pubkey && !a.input)
    throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});

  typef(
    {
      network: typef.maybe(typef.Object),
      address: typef.maybe(typef.String),
      hash: typef.maybe(typef.BufferN(20)),
      output: typef.maybe(typef.BufferN(60)),
      pubkey: typef.maybe(ecc.isPoint),
      signature: typef.maybe(bscript.isCanonicalScriptSignature),
      input: typef.maybe(typef.Buffer),
      colorId: typef.maybe(types.ColorId),
    },
    a,
  );

  const _address = coloredAddressFn(a.address!);

  const network = a.network || PROD_NETWORK;
  const o: Payment = { name: 'cp2pkh', network };

  lazy.prop(o, 'address', () => {
    if (!o.hash) return;
    if (!o.colorId) return;

    const payload = Buffer.allocUnsafe(54);
    payload.writeUInt8(network.coloredPubKeyHash, 0);
    o.colorId.copy(payload, 1);
    o.hash.copy(payload, 34);
    return bs58check.encode(payload);
  });
  lazy.prop(o, 'hash', () => {
    if (a.output) return a.output.slice(38, 58);
    if (a.address) return _address().hash;
    if (a.pubkey || o.pubkey) return bcrypto.hash160(a.pubkey! || o.pubkey!);
  });
  lazy.prop(o, 'output', () => {
    if (!o.hash) return;
    if (!o.colorId) return;
    return bscript.compile([
      o.colorId,
      OPS.OP_COLOR,
      OPS.OP_DUP,
      OPS.OP_HASH160,
      o.hash,
      OPS.OP_EQUALVERIFY,
      OPS.OP_CHECKSIG,
    ]);
  });
  lazy.prop(o, 'pubkey', () => {
    if (!a.input) return;
    return chunksFn(a.input!)()[1] as Buffer;
  });
  lazy.prop(o, 'signature', () => {
    if (!a.input) return;
    return chunksFn(a.input!)()[0] as Buffer;
  });
  lazy.prop(o, 'input', () => {
    if (!a.pubkey) return;
    if (!a.signature) return;
    return bscript.compile([a.signature, a.pubkey]);
  });
  lazy.prop(o, 'colorId', () => {
    if (a.output) return a.output.slice(1, 34);
    if (a.address) return _address().colorId;
  });

  // extended validation
  if (opts.validate) {
    let hash: Buffer = Buffer.from([]);
    let colorId: Buffer = Buffer.from([]);
    if (a.address) {
      if (_address().version !== network.coloredPubKeyHash)
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
        a.output.length !== 60 ||
        a.output[0] !== 0x21 ||
        a.output[34] !== OPS.OP_COLOR ||
        a.output[35] !== OPS.OP_DUP ||
        a.output[36] !== OPS.OP_HASH160 ||
        a.output[37] !== 0x14 ||
        a.output[58] !== OPS.OP_EQUALVERIFY ||
        a.output[59] !== OPS.OP_CHECKSIG
      )
        throw new TypeError('Output is invalid');

      const colorId2 = a.output.slice(1, 34);
      colorId = validColorId(colorId, colorId2);
      const hash2 = a.output.slice(38, 58);
      checkHash(hash, hash2);
      hash = hash2;
    }

    if (colorId.length > 0 && !types.ColorId(colorId))
      throw new TypeError('Invalid color identifier');

    if (a.pubkey) {
      const pkh = bcrypto.hash160(a.pubkey);
      checkHash(hash, pkh);
      hash = pkh;
    }

    if (a.input) {
      const chunks = chunksFn(a.input!)();
      if (chunks.length !== 2) throw new TypeError('Input is invalid');
      if (!bscript.isCanonicalScriptSignature(chunks[0] as Buffer))
        throw new TypeError('Input has invalid signature');
      if (!ecc.isPoint(chunks[1]))
        throw new TypeError('Input has invalid pubkey');

      if (a.signature && !a.signature.equals(chunks[0] as Buffer))
        throw new TypeError('Signature mismatch');
      if (a.pubkey && !a.pubkey.equals(chunks[1] as Buffer))
        throw new TypeError('Pubkey mismatch');

      const pkh = bcrypto.hash160(chunks[1] as Buffer);
      checkHash(hash, pkh);
    }
  }

  return Object.assign(o, a);
}
