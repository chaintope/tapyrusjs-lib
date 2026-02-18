import { Network, NetworkId } from './networks';
export interface Issuer {
    name?: string;
    url?: string;
    email?: string;
}
export interface Attribute {
    trait_type: string;
    value: string | number;
    display_type?: string;
}
export type TokenType = 'reissuable' | 'non_reissuable' | 'nft';
export interface OutPoint {
    txid: Buffer;
    index: number;
}
export interface RegistryEntry {
    metadata: Metadata;
    paymentBase: Buffer;
    outPoint?: OutPoint;
}
export interface MetadataFields {
    version: string;
    name: string;
    symbol: string;
    tokenType: TokenType;
    decimals?: number;
    description?: string;
    icon?: string;
    website?: string;
    issuer?: Issuer;
    terms?: string;
    properties?: Record<string, unknown>;
    image?: string;
    animation_url?: string;
    external_url?: string;
    attributes?: Attribute[];
}
export declare class Metadata {
    static fromJSON(json: string): Metadata;
    static fetch(colorId: string, networkId: NetworkId, baseUrl?: string): Promise<RegistryEntry>;
    private static validate;
    readonly version: string;
    readonly name: string;
    readonly symbol: string;
    readonly tokenType: TokenType;
    readonly decimals?: number;
    readonly description?: string;
    readonly icon?: string;
    readonly website?: string;
    readonly issuer?: Issuer;
    readonly terms?: string;
    readonly properties?: Record<string, unknown>;
    readonly image?: string;
    readonly animation_url?: string;
    readonly external_url?: string;
    readonly attributes?: Attribute[];
    constructor(fields: MetadataFields);
    toCanonical(): string;
    digest(): Buffer;
    toObject(): MetadataFields;
    commitment(publicKey: Buffer): Buffer;
    p2cPublicKey(publicKey: Buffer): Buffer;
    p2cAddress(publicKey: Buffer, network?: Network): string;
    deriveColorId(publicKey?: Buffer, outPoint?: OutPoint): Buffer;
}
