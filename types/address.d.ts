import { Network } from './networks';
export interface Base58CheckResult {
    hash: Buffer;
    version: number;
    colorId?: Buffer;
}
export declare function fromBase58Check(address: string): Base58CheckResult;
/**
 * The version byte is not checked against the colour: this function does not
 * know the network, so it can encode an uncoloured version with a colour and a
 * coloured version without one. `toOutputScript` rejects both.
 */
export declare function toBase58Check(hash: Buffer, version: number, colorId?: Buffer): string;
export declare function fromOutputScript(output: Buffer, network?: Network): string;
export declare function toOutputScript(address: string, network?: Network): Buffer;
