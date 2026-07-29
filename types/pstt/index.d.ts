import { Signer } from '../ecpair';
import { Network } from '../networks';
import { Transaction } from '../transaction';
import { PsttRecord } from './container';
import { PsttData } from './converter';
import { MAGIC, TxModifiable } from './fields';
import { Bip32Derivation, GlobalXpub, PartialSig, PreimageMap, PsttGlobal, PsttGlobalUpdate, PsttInput, PsttInputAdd, PsttInputUpdate, PsttOutput, PsttOutputAdd, PsttOutputUpdate } from './interfaces';
import { resolveLocktime } from './locktime';
export { Bip32Derivation, GlobalXpub, PartialSig, PreimageMap, PsttData, PsttGlobal, PsttGlobalUpdate, PsttInput, PsttInputAdd, PsttInputUpdate, PsttOutput, PsttOutputAdd, PsttOutputUpdate, PsttRecord, TxModifiable, MAGIC, };
export { FinalizeContext, registerScriptSigBuilder, ScriptSigBuilder, unregisterScriptSigBuilder, } from './finalizer';
export { resolveLocktime };
export type SignatureScheme = 'ecdsa' | 'schnorr';
export interface PsttOpts {
    network: Network;
}
export interface PsttOptsOptional {
    network?: Network;
}
/**
 * A Signer that can also produce Tapyrus Schnorr signatures. `ECPair`
 * satisfies this through `privateKey`.
 */
export interface PsttSigner extends Signer {
    privateKey?: Buffer;
    signSchnorr?(hash: Buffer): Buffer;
}
export interface SignOpts {
    sighashType?: number;
    scheme?: SignatureScheme;
}
/**
 * The scheme of a partial signature value, decided by its length exactly as
 * the Tapyrus script interpreter decides it.
 */
export declare function signatureScheme(signature: Buffer): SignatureScheme;
/**
 * Pstt fulfills every role of TIP-0174.
 *
 * Creator: `new Pstt()`, `setFeatures`, `setFallbackLocktime`,
 *   `setInputsModifiable`, `setOutputsModifiable`.
 * Constructor: `addInput`, `addOutput`, `addInputOutputPair`,
 *   `finishConstruction`.
 * Updater: `updateGlobal`, `updateInput`, `updateOutput`.
 * Signer: `signInput`, `signAllInputs`, `hashForSignature`,
 *   `validateSignaturesOfInput`.
 * Combiner: `combine`.
 * Input Finalizer: `finalizeInput`, `finalizeAllInputs`.
 * Transaction Extractor: `extractTransaction`.
 */
export declare class Pstt {
    data: PsttData;
    static fromBuffer(buffer: Buffer, opts?: PsttOptsOptional): Pstt;
    static fromBase64(data: string, opts?: PsttOptsOptional): Pstt;
    static fromHex(data: string, opts?: PsttOptsOptional): Pstt;
    readonly opts: PsttOpts;
    constructor(opts?: PsttOptsOptional, data?: PsttData);
    get global(): PsttGlobal;
    get inputs(): PsttInput[];
    get outputs(): PsttOutput[];
    setFeatures(features: number): this;
    setFallbackLocktime(locktime: number): this;
    setInputsModifiable(modifiable: boolean): this;
    setOutputsModifiable(modifiable: boolean): this;
    isInputsModifiable(): boolean;
    isOutputsModifiable(): boolean;
    hasSighashSingle(): boolean;
    /**
     * Declare construction finished by clearing the Inputs Modifiable and
     * Outputs Modifiable flags.
     */
    finishConstruction(): this;
    addInput(input: PsttInputAdd): this;
    addOutput(output: PsttOutputAdd): this;
    /**
     * Add an input and an output at once, after the existing ones. This is the
     * only way to extend a PSTT that carries a SIGHASH_SINGLE signature: adding
     * in pairs keeps every existing input at the position of its corresponding
     * output, and keeps the added input paired with an output of its own.
     */
    addInputOutputPair(input: PsttInputAdd, output: PsttOutputAdd): this;
    /**
     * The signature hash covers the features and the locktime of the
     * transaction, so both are guarded here the way `updateInput` guards the
     * per-input locktime fields: a PSTT that already carries a signature can not
     * have either changed underneath it.
     */
    updateGlobal(update: PsttGlobalUpdate): this;
    updateInput(inputIndex: number, update: PsttInputUpdate): this;
    updateOutput(outputIndex: number, update: PsttOutputUpdate): this;
    /**
     * The locktime of the transaction, resolved from
     * PSTT_GLOBAL_FALLBACK_LOCKTIME and the per-input required locktimes.
     */
    get locktime(): number;
    /**
     * The transaction the fields describe, with the real sequence numbers and
     * no scriptSigs. This is the transaction the signature hash is computed on.
     */
    getTransaction(): Transaction;
    /**
     * The transaction that identifies this PSTT: the same fields with the
     * sequence number of every input set to 0, because sequence numbers may
     * still change after creation.
     */
    getIdentificationTransaction(): Transaction;
    /**
     * The identification txid (hashMalFix), in display order.
     */
    getId(): string;
    /**
     * The output being spent by an input, taken from PSTT_IN_UTXO after
     * verifying that its txid matches PSTT_IN_PREVIOUS_TXID.
     */
    getPrevOutput(inputIndex: number): {
        script: Buffer;
        value: number;
    };
    /**
     * The scriptCode used in the signature hash: the redeem script for a P2SH or
     * CP2SH input, the complete scriptPubKey otherwise (including the
     * `<color identifier> OP_COLOR` prefix of a CP2PKH output).
     */
    getScriptCode(inputIndex: number): Buffer;
    hashForSignature(inputIndex: number, sighashType: number): Buffer;
    signInput(inputIndex: number, keyPair: PsttSigner, opts?: SignOpts): this;
    /**
     * Sign every input the key belongs to. Inputs the key cannot sign, or that
     * request a sighash type this call does not produce, are skipped.
     */
    signAllInputs(keyPair: PsttSigner, opts?: SignOpts): this;
    /**
     * Record a signature, whether this instance produced it or another party did,
     * and apply the PSTT_GLOBAL_TX_MODIFIABLE updates the Signer role requires.
     * Every rule TIP-0174 places on a Signer is enforced here, so that a
     * signature imported from elsewhere cannot bypass a check `signInput` makes.
     */
    addPartialSig(inputIndex: number, partialSig: PartialSig): this;
    inputHasPubkey(inputIndex: number, pubkey: Buffer): boolean;
    validateSignaturesOfAllInputs(): boolean;
    validateSignaturesOfInput(inputIndex: number, pubkey?: Buffer): boolean;
    /**
     * Combine other PSTTs into this one.
     *
     * All or nothing: the PSTTs are combined one after another, but if any of
     * them is rejected the ones already applied are rolled back, so a caller
     * that catches the error still holds the PSTT it had before the call.
     */
    combine(...others: Pstt[]): this;
    /**
     * Finalize every input that is not finalized yet.
     */
    finalizeAllInputs(): this;
    finalizeInput(inputIndex: number): this;
    extractTransaction(): Transaction;
    toBuffer(): Buffer;
    toBase64(): string;
    toHex(): string;
    private buildTransaction;
    private buildFinalScriptSig;
    private pushInput;
    private pushOutput;
    /**
     * TIP-0174 treats an absent PSTT_GLOBAL_TX_MODIFIABLE as "not modifiable", so
     * a Constructor may only add while the corresponding flag is set. A PSTT this
     * process created starts with both flags set (see `emptyData`), which is what
     * lets a Creator build one before deciding to fix it.
     */
    private checkModifiable;
    /**
     * An Updater must not change the sequence number of a signed input, nor of
     * any input while some SIGHASH_ALL signature (without SIGHASH_ANYONECANPAY)
     * commits to it.
     *
     * A finalized input counts as signed even though its PSTT_IN_PARTIAL_SIG
     * records are gone: the signatures moved into PSTT_IN_FINAL_SCRIPTSIG, where
     * their sighash types are no longer readable as records. Which of them commit
     * to which sequence number can therefore no longer be decided, so any
     * finalized input blocks every sequence change in the PSTT.
     */
    private checkCanChangeSequence;
    /**
     * TIP-0174 requires every signature of an input to use the sighash type
     * PSTT_IN_SIGHASH_TYPE requests, so an Updater that changes the request once
     * the input holds a signature leaves the input contradicting itself — and
     * `addPartialSig`, which enforces the same rule from the Signer's side, would
     * then reject the very signatures already recorded.
     *
     * A finalized input counts as signed: its signatures moved into
     * PSTT_IN_FINAL_SCRIPTSIG, and the Input Finalizer removed the record this
     * would recreate.
     */
    private checkCanChangeSighashType;
    /**
     * TIP-0174 lets a Combiner resolve a conflicting record by keeping either
     * value, and `mergeRecords` keeps this copy's. PSTT_IN_SEQUENCE is the one
     * record where that silently destroys information: the identification txid is
     * computed with every sequence number set to 0, so two copies that disagree
     * about one still identify as the same PSTT, and keeping this copy's value
     * would invalidate every signature of the other copy that commits to the
     * other one. This is therefore the conflict the Combiner refuses rather than
     * resolves.
     */
    private checkSequencesAgree;
    /**
     * Every signature commits to the locktime, so neither a Constructor nor an
     * Updater may change the locktime a PSTT resolves to once it holds one.
     */
    private checkLocktimeUnchanged;
    private checkSighashType;
    private resolveSighashType;
    private applySignerModifiableRules;
    private setModifiableFlag;
    /**
     * PSTT_GLOBAL_TX_MODIFIABLE records what the signatures collected so far
     * still allow, so once a PSTT holds one, a change to the field may only
     * tighten it. Setting Inputs Modifiable or Outputs Modifiable again would
     * re-open the very modification a Signer closed by signing, and clearing Has
     * SIGHASH_SINGLE would drop the pairing rule that keeps a SIGHASH_SINGLE
     * signature covering its own output — either way `addInput`, `addOutput` and
     * `finalizeInput`, which all consult this field, would let through a change
     * that invalidates the existing signatures.
     */
    private checkModifiableTightens;
    private hasModifiableFlag;
    private hasSignatures;
    /**
     * The Input Finalizer removes the PSTT_IN_PARTIAL_SIG records of an input it
     * finalizes, so a signature added afterwards would recreate a record the
     * format says is no longer there, next to the finalized scriptSig.
     */
    private checkNotFinalized;
    private checkInputIndex;
    private checkOutputIndex;
}
