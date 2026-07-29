import { RawPstt } from './container';
import { PsttGlobal, PsttInput, PsttOutput } from './interfaces';
declare function decodeDerivationPath(value: Buffer, name: string): {
    masterFingerprint: Buffer;
    path: string;
};
declare function encodeDerivationPath(masterFingerprint: Buffer, path: string): Buffer;
export interface PsttData {
    global: PsttGlobal;
    inputs: PsttInput[];
    outputs: PsttOutput[];
}
export declare function fromRaw(raw: RawPstt): PsttData;
export declare function toRaw(data: PsttData): RawPstt;
export { decodeDerivationPath, encodeDerivationPath };
