import { Network } from '../networks';
import { Payment, PaymentFunction, StackFunction } from './index';
export declare function fromOutputScript(output: Buffer, network?: Network): Payment;
export declare function addressFn(address: string): () => {
    version: number;
    hash: Buffer;
};
export declare function coloredAddressFn(address: string): () => {
    version: number;
    colorId: Buffer;
    hash: Buffer;
};
export declare function chunksFn(script: Buffer): StackFunction;
export declare function redeemFn(a: Payment, network: Network | undefined): PaymentFunction;
export declare function checkHash(hash: Buffer, hash2: Buffer): void;
export declare function validColorId(colorId: Buffer, newColorId: Buffer): Buffer;
export declare function stacksEqual(a: Buffer[], b: Buffer[]): boolean;
export declare function checkInput(_chunksFn: StackFunction, _redeemFn: PaymentFunction, hashForCheck: Buffer): Buffer | null;
export declare function checkRedeem(a: Payment, network: Network, _redeemFn: PaymentFunction, hashForCheck: Buffer): void;
