export interface Network {
    messagePrefix: string;
    bip32: Bip32;
    pubKeyHash: number;
    scriptHash: number;
    coloredPubKeyHash: number;
    coloredScriptHash: number;
    wif: number;
}
interface Bip32 {
    public: number;
    private: number;
}
export declare const prod: Network;
export declare const dev: Network;
export declare enum NetworkId {
    TAPYRUS_API = 15215628,
    TESTNET = 1939510133
}
export {};
