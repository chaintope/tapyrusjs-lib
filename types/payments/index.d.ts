import { Network } from '../networks';
import { cp2pkh } from './cp2pkh';
import { cp2sh } from './cp2sh';
import { p2data as embed } from './embed';
import { p2ms } from './p2ms';
import { p2pk } from './p2pk';
import { p2pkh } from './p2pkh';
import { p2sh } from './p2sh';
import * as util from './util';
export interface Payment {
    name?: string;
    network?: Network;
    output?: Buffer;
    data?: Buffer[];
    m?: number;
    n?: number;
    pubkeys?: Buffer[];
    input?: Buffer;
    signatures?: Buffer[];
    pubkey?: Buffer;
    signature?: Buffer;
    address?: string;
    hash?: Buffer;
    redeem?: Payment;
    colorId?: Buffer;
}
export type PaymentCreator = (a: Payment, opts?: PaymentOpts) => Payment;
export type PaymentFunction = () => Payment;
export interface PaymentOpts {
    validate?: boolean;
    allowIncomplete?: boolean;
}
export type StackElement = Buffer | number;
export type Stack = StackElement[];
export type StackFunction = () => Stack;
export { cp2pkh, cp2sh, embed, p2ms, p2pk, p2pkh, p2sh, util };
