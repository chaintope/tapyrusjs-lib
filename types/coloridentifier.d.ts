/**
 * The output a token is issued from. `txid` holds the hashMalFix of the
 * transaction in the byte order it is serialized in, which is the reverse of
 * the order it is displayed in.
 */
export interface OutPoint {
    txid: Buffer;
    index: number;
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
export declare function reissuable(scriptPubKey: Buffer): Buffer;
/**
 * The colour identifier of a non-reissuable token. It is derived from the
 * output the issuance spends, so the whole supply is fixed by the one
 * transaction that creates it.
 */
export declare function nonReissuable(outPoint: OutPoint): Buffer;
/**
 * The colour identifier of an NFT. It is derived the same way as a
 * non-reissuable token, and tapyrus-core additionally caps the supply at one.
 */
export declare function nft(outPoint: OutPoint): Buffer;
