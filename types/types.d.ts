export declare function UInt31(value: number): boolean;
export declare function BIP32Path(value: string): boolean;
export declare namespace BIP32Path {
    var toJSON: () => string;
}
export declare function Signer(obj: any): boolean;
/**
 * A Tapyrus colour identifier: one token type byte followed by a 32 byte
 * payload. tapyrus-core rejects any other type byte, and rejects an all-zero
 * payload, both when decoding an address and when executing OP_COLOR.
 */
export declare const COLOR_ID_REISSUABLE = 193;
export declare const COLOR_ID_NON_REISSUABLE = 194;
export declare const COLOR_ID_NFT = 195;
export declare function ColorId(value: unknown): boolean;
export declare namespace ColorId {
    var toJSON: () => string;
}
export declare function Satoshi(value: number): boolean;
export declare const ECPoint: any;
export declare const Network: any;
export declare const Buffer256bit: any;
export declare const Hash160bit: any;
export declare const Hash256bit: any;
export declare const Number: any;
export declare const Array: any;
export declare const Boolean: any;
export declare const String: any;
export declare const Buffer: any;
export declare const Hex: any;
export declare const maybe: any;
export declare const tuple: any;
export declare const UInt8: any;
export declare const UInt32: any;
export declare const Function: any;
export declare const BufferN: any;
export declare const Null: any;
export declare const oneOf: any;
