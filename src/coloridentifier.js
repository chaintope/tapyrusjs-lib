'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.reissuable = reissuable;
exports.nonReissuable = nonReissuable;
exports.nft = nft;
const crypto = require('./crypto');
const script_1 = require('./script');
const types_1 = require('./types');
const typeforce = require('typeforce');
const TXID_LENGTH = 32;
const OUT_POINT_LENGTH = TXID_LENGTH + 4;
const OutPointSchema = typeforce.compile({
  txid: types_1.Hash256bit,
  index: types_1.UInt32,
});
function colorId(type, payload) {
  const result = Buffer.alloc(types_1.COLOR_ID_LENGTH);
  result[0] = type;
  payload.copy(result, 1);
  return result;
}
function serializeOutPoint(outPoint) {
  typeforce(OutPointSchema, outPoint);
  const buffer = Buffer.alloc(OUT_POINT_LENGTH);
  outPoint.txid.copy(buffer, 0);
  buffer.writeUInt32LE(outPoint.index, TXID_LENGTH);
  return buffer;
}
// The same test as tapyrus-core's CScript::IsColoredScript: an OP_COLOR
// opcode anywhere in the script. A byte 0xbc inside push data is not one.
function containsOpColor(script) {
  const chunks = (0, script_1.decompile)(script);
  return !!chunks && chunks.indexOf(script_1.OPS.OP_COLOR) !== -1;
}
/**
 * The colour identifier of a reissuable token, derived from the scriptPubKey of
 * the TPC output the issuance spends. Because the identity is the script and
 * not one output, the issuer mints more of the same token by spending another
 * output locked by that same script.
 *
 * `scriptPubKey` must not itself carry a colour, so a coloured script such as
 * CP2PKH is refused. tapyrus-core's RPC and its validation of an issuance
 * likewise refuse a token whose input is another token's script.
 */
function reissuable(scriptPubKey) {
  typeforce(typeforce.Buffer, scriptPubKey);
  if (containsOpColor(scriptPubKey)) {
    throw new TypeError('scriptPubKey must not be a colored script');
  }
  return colorId(types_1.COLOR_ID_REISSUABLE, crypto.sha256(scriptPubKey));
}
/**
 * The colour identifier of a non-reissuable token. It is derived from the
 * output the issuance spends, so the whole supply is fixed by the one
 * transaction that creates it.
 */
function nonReissuable(outPoint) {
  return colorId(
    types_1.COLOR_ID_NON_REISSUABLE,
    crypto.sha256(serializeOutPoint(outPoint)),
  );
}
/**
 * The colour identifier of an NFT. It is derived the same way as a
 * non-reissuable token, and tapyrus-core additionally caps the supply at one.
 */
function nft(outPoint) {
  return colorId(
    types_1.COLOR_ID_NFT,
    crypto.sha256(serializeOutPoint(outPoint)),
  );
}
