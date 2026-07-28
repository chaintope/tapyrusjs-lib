import { BIP32Factory, BIP32Interface } from 'bip32';
import * as ecc from 'tiny-secp256k1';
import * as address from './address';
import * as bufferutils from './bufferutils';
import * as crypto from './crypto';
import * as ECPair from './ecpair';
import * as networks from './networks';
import * as payments from './payments';
import * as schnorr from './schnorr';
import * as script from './script';

const bip32 = BIP32Factory(ecc);

export {
  BIP32Interface,
  ECPair,
  address,
  bip32,
  bufferutils,
  crypto,
  networks,
  payments,
  schnorr,
  script,
};

export { Block } from './block';
export {
  Metadata,
  Issuer,
  Attribute,
  MetadataFields,
  TokenType,
  OutPoint,
  RegistryEntry,
} from './metadata';
export { Psbt, PsbtTxInput, PsbtTxOutput } from './psbt';
export {
  Bip32Derivation,
  FinalizeContext,
  GlobalXpub,
  PartialSig,
  PreimageMap,
  Pstt,
  PsttData,
  PsttGlobal,
  PsttGlobalUpdate,
  PsttInput,
  PsttInputAdd,
  PsttInputUpdate,
  PsttOptsOptional,
  PsttOutput,
  PsttOutputAdd,
  PsttOutputUpdate,
  PsttRecord,
  PsttSigner,
  registerScriptSigBuilder,
  resolveLocktime,
  ScriptSigBuilder,
  SignatureScheme,
  TxModifiable,
  unregisterScriptSigBuilder,
} from './pstt';
export {
  GlobalTypes as PsttGlobalTypes,
  InputTypes as PsttInputTypes,
  OutputTypes as PsttOutputTypes,
} from './pstt/fields';
export { OPS as opcodes } from './script';
export { Transaction } from './transaction';
export { TransactionBuilder } from './transaction_builder';

export { ECPairInterface, Signer, SignerAsync } from './ecpair';
export { Network, NetworkId } from './networks';
export {
  Payment,
  PaymentCreator,
  PaymentOpts,
  Stack,
  StackElement,
} from './payments';
export { OpCode } from './script';
export { Input as TxInput, Output as TxOutput } from './transaction';
