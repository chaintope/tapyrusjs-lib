// Input Finalizer of TIP-0174: turning the collected records of an input into
// the scriptSig that satisfies the script of the output being spent.
//
// The script types are held in a registry rather than in a switch inside Pstt,
// so that support for a further template can be added without changing the
// class. `scriptSigStack` receives the meaningful script — the redeem script
// for a P2SH or CP2SH input, the scriptPubKey otherwise — and returns the stack
// of the scriptSig; Pstt appends the redeem script for the P2SH types.

import * as classify from '../classify';
import * as payments from '../payments';
import { OPS } from '../script';
import { PartialSig } from './interfaces';

export interface FinalizeContext {
  /** Index of the input, used only to build error messages. */
  inputIndex: number;
  /** The meaningful script: the redeem script for P2SH/CP2SH, else the scriptPubKey. */
  script: Buffer;
  partialSig: PartialSig[];
}

export type ScriptSigBuilder = (
  context: FinalizeContext,
) => Array<Buffer | number>;

const builders: { [scriptType: string]: ScriptSigBuilder } = {};

/**
 * Register the scriptSig builder of a script type, replacing any builder
 * already registered for it.
 */
export function registerScriptSigBuilder(
  scriptType: string,
  builder: ScriptSigBuilder,
): void {
  builders[scriptType] = builder;
}

/**
 * Drop the scriptSig builder of a script type, so that finalizing an input of
 * that type is reported as unsupported again.
 */
export function unregisterScriptSigBuilder(scriptType: string): void {
  delete builders[scriptType];
}

export function scriptSigBuilderFor(
  scriptType: string,
): ScriptSigBuilder | undefined {
  return builders[scriptType];
}

function onlySignature(context: FinalizeContext): PartialSig {
  if (context.partialSig.length !== 1)
    throw new Error(
      `Input #${context.inputIndex} needs exactly one signature to ` +
        `finalize, found ${context.partialSig.length}`,
    );
  return context.partialSig[0];
}

function pubkeyAndSignature(context: FinalizeContext): Array<Buffer | number> {
  const sig = onlySignature(context);
  return [sig.signature, sig.pubkey];
}

registerScriptSigBuilder(classify.types.P2PKH, pubkeyAndSignature);
registerScriptSigBuilder(classify.types.CP2PKH, pubkeyAndSignature);

registerScriptSigBuilder(classify.types.P2PK, context => [
  onlySignature(context).signature,
]);

registerScriptSigBuilder(classify.types.P2MS, context => {
  const p2ms = payments.p2ms({ output: context.script });
  const sigs = p2ms
    .pubkeys!.map(pubkey =>
      context.partialSig.find(sig => sig.pubkey.equals(pubkey)),
    )
    .filter((sig): sig is PartialSig => sig !== undefined);
  if (sigs.length < p2ms.m!)
    throw new Error(
      `Input #${context.inputIndex} has ${sigs.length} of the ${p2ms.m} ` +
        `signatures needed to finalize`,
    );
  return [OPS.OP_0, ...sigs.slice(0, p2ms.m!).map(sig => sig.signature)];
});
