// {colorIdentifier} OP_COLOR OP_DUP OP_HASH160 {pubKeyHash} OP_EQUALVERIFY OP_CHECKSIG

import * as bscript from '../../script';
import { OPS } from '../../script';
import * as types from '../../types';

export function check(script: Buffer | Array<number | Buffer>): boolean {
  const buffer = bscript.compile(script);

  return (
    buffer.length === 60 &&
    buffer[0] === 0x21 &&
    types.ColorId(buffer.slice(1, 1 + types.COLOR_ID_LENGTH)) &&
    buffer[34] === OPS.OP_COLOR &&
    buffer[35] === OPS.OP_DUP &&
    buffer[36] === OPS.OP_HASH160 &&
    buffer[37] === 0x14 &&
    buffer[58] === OPS.OP_EQUALVERIFY &&
    buffer[59] === OPS.OP_CHECKSIG
  );
}
check.toJSON = (): string => {
  return 'colored pubKeyHash output';
};
