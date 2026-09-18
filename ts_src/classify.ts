import { decompile } from './script';
import * as coloredPubKeyHash from './templates/coloredpubkeyhash';
import * as coloredScriptHash from './templates/coloredscripthash';
import * as multisig from './templates/multisig';
import * as nullData from './templates/nulldata';
import * as pubKey from './templates/pubkey';
import * as pubKeyHash from './templates/pubkeyhash';
import * as scriptHash from './templates/scripthash';

const types = {
  P2MS: 'multisig' as string,
  NONSTANDARD: 'nonstandard' as string,
  NULLDATA: 'nulldata' as string,
  P2PK: 'pubkey' as string,
  P2PKH: 'pubkeyhash' as string,
  P2SH: 'scripthash' as string,
  CP2PKH: 'coloredpubkeyhash',
  CP2SH: 'coloredscripthash',
};

function classifyOutput(script: Buffer): string {
  if (pubKeyHash.output.check(script)) return types.P2PKH;
  if (scriptHash.output.check(script)) return types.P2SH;
  if (coloredPubKeyHash.output.check(script)) return types.CP2PKH;
  if (coloredScriptHash.output.check(script)) return types.CP2SH;

  // XXX: optimization, below functions .decompile before use
  const chunks = decompile(script);
  if (!chunks) throw new TypeError('Invalid script');

  if (multisig.output.check(chunks)) return types.P2MS;
  if (pubKey.output.check(chunks)) return types.P2PK;
  if (nullData.output.check(chunks)) return types.NULLDATA;

  return types.NONSTANDARD;
}

function classifyInput(script: Buffer, allowIncomplete?: boolean): string {
  // XXX: optimization, below functions .decompile before use
  const chunks = decompile(script);
  if (!chunks) throw new TypeError('Invalid script');

  if (pubKeyHash.input.check(chunks)) return types.P2PKH;
  if (scriptHash.input.check(chunks, allowIncomplete)) return types.P2SH;
  if (multisig.input.check(chunks, allowIncomplete)) return types.P2MS;
  if (pubKey.input.check(chunks)) return types.P2PK;

  return types.NONSTANDARD;
}

export { classifyInput as input, classifyOutput as output, types };
