'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.oneOf = exports.Null = exports.BufferN = exports.Function = exports.UInt32 = exports.UInt8 = exports.tuple = exports.maybe = exports.Hex = exports.Buffer = exports.String = exports.Boolean = exports.Array = exports.Number = exports.Hash256bit = exports.Hash160bit = exports.Buffer256bit = exports.Network = exports.ECPoint = exports.COLOR_ID_NFT = exports.COLOR_ID_NON_REISSUABLE = exports.COLOR_ID_REISSUABLE = void 0;
exports.UInt31 = UInt31;
exports.BIP32Path = BIP32Path;
exports.Signer = Signer;
exports.ColorId = ColorId;
exports.Satoshi = Satoshi;
const typeforce = require('typeforce');
const UINT31_MAX = Math.pow(2, 31) - 1;
function UInt31(value) {
  return typeforce.UInt32(value) && value <= UINT31_MAX;
}
function BIP32Path(value) {
  return typeforce.String(value) && !!value.match(/^(m\/)?(\d+'?\/)*\d+'?$/);
}
BIP32Path.toJSON = () => {
  return 'BIP32 derivation path';
};
function Signer(obj) {
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
exports.COLOR_ID_REISSUABLE = 0xc1;
exports.COLOR_ID_NON_REISSUABLE = 0xc2;
exports.COLOR_ID_NFT = 0xc3;
const COLOR_ID_LENGTH = 33;
const COLOR_ID_TYPES = [
  exports.COLOR_ID_REISSUABLE,
  exports.COLOR_ID_NON_REISSUABLE,
  exports.COLOR_ID_NFT,
];
function isBuffer(value) {
  return typeforce.Buffer(value);
}
function ColorId(value) {
  if (!isBuffer(value)) return false;
  if (value.length !== COLOR_ID_LENGTH) return false;
  if (COLOR_ID_TYPES.indexOf(value[0]) < 0) return false;
  // an all-zero payload is not a colour: SCRIPT_ERR_OP_COLORID_INVALID
  return value.slice(1).some(byte => byte !== 0);
}
ColorId.toJSON = () => {
  return 'color identifier';
};
const SATOSHI_MAX = 21 * 1e14;
function Satoshi(value) {
  return typeforce.UInt53(value) && value <= SATOSHI_MAX;
}
// external dependent types
exports.ECPoint = typeforce.quacksLike('Point');
// exposed, external API
exports.Network = typeforce.compile({
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
exports.Buffer256bit = typeforce.BufferN(32);
exports.Hash160bit = typeforce.BufferN(20);
exports.Hash256bit = typeforce.BufferN(32);
exports.Number = typeforce.Number; // tslint:disable-line variable-name
exports.Array = typeforce.Array;
exports.Boolean = typeforce.Boolean; // tslint:disable-line variable-name
exports.String = typeforce.String; // tslint:disable-line variable-name
exports.Buffer = typeforce.Buffer;
exports.Hex = typeforce.Hex;
exports.maybe = typeforce.maybe;
exports.tuple = typeforce.tuple;
exports.UInt8 = typeforce.UInt8;
exports.UInt32 = typeforce.UInt32;
exports.Function = typeforce.Function;
exports.BufferN = typeforce.BufferN;
exports.Null = typeforce.Null;
exports.oneOf = typeforce.oneOf;
