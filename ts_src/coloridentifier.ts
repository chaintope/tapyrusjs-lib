import * as crypto from './crypto';
import {
  COLOR_ID_LENGTH,
  COLOR_ID_NFT,
  COLOR_ID_NON_REISSUABLE,
  COLOR_ID_REISSUABLE,
} from './types';

const typeforce = require('typeforce');

/**
 * The output a token is issued from. `txid` holds the hashMalFix of the
 * transaction in the byte order it is serialized in, which is the reverse of
 * the order it is displayed in.
 */
export interface OutPoint {
  txid: Buffer;
  index: number;
}

const TXID_LENGTH = 32;
const OUT_POINT_LENGTH = TXID_LENGTH + 4;

function colorId(type: number, payload: Buffer): Buffer {
  const result = Buffer.alloc(COLOR_ID_LENGTH);
  result[0] = type;
  payload.copy(result, 1);
  return result;
}

function serializeOutPoint(outPoint: OutPoint): Buffer {
  typeforce(
    { txid: typeforce.BufferN(TXID_LENGTH), index: typeforce.UInt32 },
    outPoint,
  );
  const buffer = Buffer.alloc(OUT_POINT_LENGTH);
  outPoint.txid.copy(buffer, 0);
  buffer.writeUInt32LE(outPoint.index, TXID_LENGTH);
  return buffer;
}

/**
 * The colour identifier of a reissuable token, derived from the scriptPubKey of
 * the TPC output the issuance spends. Because the identity is the script and
 * not one output, the issuer mints more of the same token by spending another
 * output locked by that same script.
 *
 * `scriptPubKey` must not itself carry a colour: tapyrus-core derives no colour
 * from a script containing OP_COLOR.
 */
export function reissuable(scriptPubKey: Buffer): Buffer {
  typeforce(typeforce.Buffer, scriptPubKey);
  return colorId(COLOR_ID_REISSUABLE, crypto.sha256(scriptPubKey));
}

/**
 * The colour identifier of a non-reissuable token. It is derived from the
 * output the issuance spends, so the whole supply is fixed by the one
 * transaction that creates it.
 */
export function nonReissuable(outPoint: OutPoint): Buffer {
  return colorId(
    COLOR_ID_NON_REISSUABLE,
    crypto.sha256(serializeOutPoint(outPoint)),
  );
}

/**
 * The colour identifier of an NFT. It is derived the same way as a
 * non-reissuable token, and tapyrus-core additionally caps the supply at one.
 */
export function nft(outPoint: OutPoint): Buffer {
  return colorId(COLOR_ID_NFT, crypto.sha256(serializeOutPoint(outPoint)));
}
