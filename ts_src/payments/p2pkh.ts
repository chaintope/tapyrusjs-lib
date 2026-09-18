import * as bcrypto from '../crypto';
import { prod as PROD_NETWORK } from '../networks';
import * as bscript from '../script';
import { Payment, PaymentOpts } from './index';
import * as lazy from './lazy';
import { addressFn, checkHash, chunksFn } from './util';

const typef = require('typeforce');
const OPS = bscript.OPS;
const ecc = require('tiny-secp256k1');

const bs58check = require('bs58check');

// input: {signature} {pubkey}
// output: OP_DUP OP_HASH160 {hash160(pubkey)} OP_EQUALVERIFY OP_CHECKSIG
export function p2pkh(a: Payment, opts?: PaymentOpts): Payment {
  if (!a.address && !a.hash && !a.output && !a.pubkey && !a.input)
    throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});

  typef(
    {
      network: typef.maybe(typef.Object),
      address: typef.maybe(typef.String),
      hash: typef.maybe(typef.BufferN(20)),
      output: typef.maybe(typef.BufferN(25)),

      pubkey: typef.maybe(ecc.isPoint),
      signature: typef.maybe(bscript.isCanonicalScriptSignature),
      input: typef.maybe(typef.Buffer),
    },
    a,
  );

  const _address = addressFn(a.address!);

  const network = a.network || PROD_NETWORK;
  const o: Payment = { name: 'p2pkh', network };

  lazy.prop(o, 'address', () => {
    if (!o.hash) return;

    const payload = Buffer.allocUnsafe(21);
    payload.writeUInt8(network.pubKeyHash, 0);
    o.hash.copy(payload, 1);
    return bs58check.encode(payload);
  });
  lazy.prop(o, 'hash', () => {
    if (a.output) return a.output.slice(3, 23);
    if (a.address) return _address().hash;
    if (a.pubkey || o.pubkey) return bcrypto.hash160(a.pubkey! || o.pubkey!);
  });
  lazy.prop(o, 'output', () => {
    if (!o.hash) return;
    return bscript.compile([
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

  // extended validation
  if (opts.validate) {
    let hash: Buffer = Buffer.from([]);
    if (a.address) {
      if (_address().version !== network.pubKeyHash)
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
        a.output.length !== 25 ||
        a.output[0] !== OPS.OP_DUP ||
        a.output[1] !== OPS.OP_HASH160 ||
        a.output[2] !== 0x14 ||
        a.output[23] !== OPS.OP_EQUALVERIFY ||
        a.output[24] !== OPS.OP_CHECKSIG
      )
        throw new TypeError('Output is invalid');

      const hash2 = a.output.slice(3, 23);
      checkHash(hash, hash2);
      hash = hash2;
    }

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
