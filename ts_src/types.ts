const typeforce = require('typeforce');

const UINT31_MAX: number = Math.pow(2, 31) - 1;
export function UInt31(value: number): boolean {
  return typeforce.UInt32(value) && value <= UINT31_MAX;
}

export function BIP32Path(value: string): boolean {
  return typeforce.String(value) && !!value.match(/^(m\/)?(\d+'?\/)*\d+'?$/);
}
BIP32Path.toJSON = (): string => {
  return 'BIP32 derivation path';
};

export function Signer(obj: any): boolean {
  return (
    (typeforce.Buffer(obj.publicKey) ||
      typeof obj.getPublicKey === 'function') &&
    typeof obj.sign === 'function'
  );
}

/**
 * A Tapyrus colour identifier: one token type byte followed by a 32 byte
 * payload. tapyrus-core rejects any other type byte, and rejects an all-zero
 * payload, both when decoding an address and when executing OP_COLOR.
 */
export const COLOR_ID_REISSUABLE = 0xc1;
export const COLOR_ID_NON_REISSUABLE = 0xc2;
export const COLOR_ID_NFT = 0xc3;

const COLOR_ID_LENGTH = 33;
const COLOR_ID_TYPES = [
  COLOR_ID_REISSUABLE,
  COLOR_ID_NON_REISSUABLE,
  COLOR_ID_NFT,
];

function isBuffer(value: unknown): value is Buffer {
  return typeforce.Buffer(value);
}

export function ColorId(value: unknown): boolean {
  if (!isBuffer(value)) return false;
  if (value.length !== COLOR_ID_LENGTH) return false;
  if (COLOR_ID_TYPES.indexOf(value[0]) < 0) return false;
  // an all-zero payload is not a colour: SCRIPT_ERR_OP_COLORID_INVALID
  return value.slice(1).some(byte => byte !== 0);
}
ColorId.toJSON = (): string => {
  return 'color identifier';
};

const SATOSHI_MAX: number = 21 * 1e14;
export function Satoshi(value: number): boolean {
  return typeforce.UInt53(value) && value <= SATOSHI_MAX;
}

// external dependent types
export const ECPoint = typeforce.quacksLike('Point');

// exposed, external API
export const Network = typeforce.compile({
  messagePrefix: typeforce.oneOf(typeforce.Buffer, typeforce.String),
  bip32: {
    public: typeforce.UInt32,
    private: typeforce.UInt32,
  },
  pubKeyHash: typeforce.UInt8,
  scriptHash: typeforce.UInt8,
  coloredPubKeyHash: typeforce.UInt8,
  coloredScriptHash: typeforce.UInt8,
  wif: typeforce.UInt8,
});

export const Buffer256bit = typeforce.BufferN(32);
export const Hash160bit = typeforce.BufferN(20);
export const Hash256bit = typeforce.BufferN(32);
export const Number = typeforce.Number; // tslint:disable-line variable-name
export const Array = typeforce.Array;
export const Boolean = typeforce.Boolean; // tslint:disable-line variable-name
export const String = typeforce.String; // tslint:disable-line variable-name
export const Buffer = typeforce.Buffer;
export const Hex = typeforce.Hex;
export const maybe = typeforce.maybe;
export const tuple = typeforce.tuple;
export const UInt8 = typeforce.UInt8;
export const UInt32 = typeforce.UInt32;
export const Function = typeforce.Function;
export const BufferN = typeforce.BufferN;
export const Null = typeforce.Null;
export const oneOf = typeforce.oneOf;
