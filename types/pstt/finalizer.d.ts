import { PartialSig } from './interfaces';
export interface FinalizeContext {
    /** Index of the input, used only to build error messages. */
    inputIndex: number;
    /** The meaningful script: the redeem script for P2SH/CP2SH, else the scriptPubKey. */
    script: Buffer;
    partialSig: PartialSig[];
}
export type ScriptSigBuilder = (context: FinalizeContext) => Array<Buffer | number>;
/**
 * Register the scriptSig builder of a script type, replacing any builder
 * already registered for it.
 */
export declare function registerScriptSigBuilder(scriptType: string, builder: ScriptSigBuilder): void;
/**
 * Drop the scriptSig builder of a script type, so that finalizing an input of
 * that type is reported as unsupported again.
 */
export declare function unregisterScriptSigBuilder(scriptType: string): void;
export declare function scriptSigBuilderFor(scriptType: string): ScriptSigBuilder | undefined;
