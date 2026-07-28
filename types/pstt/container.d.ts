/**
 * One key-value record of a PSTT map.
 */
export interface PsttRecord {
    type: number;
    keydata: Buffer;
    value: Buffer;
}
/**
 * The complete key of a record (`<keytype>` and `<keydata>`) as a string, for
 * the uniqueness rule of a map and for the deduplication a Combiner performs.
 * Both must agree on what "the same key" means, so there is one definition.
 */
export declare function recordKey(record: PsttRecord): string;
/**
 * A PSTT as a plain list of records per map, before any field is interpreted.
 */
export interface RawPstt {
    global: PsttRecord[];
    inputs: PsttRecord[][];
    outputs: PsttRecord[][];
}
declare function encodeCompactSize(value: number): Buffer;
/**
 * Serialize one record as <keylen> <keytype> <keydata> <valuelen> <valuedata>.
 */
export declare function encodeRecord(record: PsttRecord): Buffer;
/**
 * Split the raw byte stream into the global map and one map per input/output.
 */
export declare function decode(buffer: Buffer): RawPstt;
export declare function encode(raw: RawPstt): Buffer;
export { encodeCompactSize };
