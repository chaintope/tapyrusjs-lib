declare const types: {
    P2MS: string;
    NONSTANDARD: string;
    NULLDATA: string;
    P2PK: string;
    P2PKH: string;
    P2SH: string;
    CP2PKH: string;
    CP2SH: string;
};
declare function classifyOutput(script: Buffer): string;
declare function classifyInput(script: Buffer, allowIncomplete?: boolean): string;
export { classifyInput as input, classifyOutput as output, types };
