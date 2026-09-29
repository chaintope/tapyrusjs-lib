// {colorIdentifier} OP_COLOR OP_HASH160 {scriptHash} OP_EQUAL

import * as bscript from '../../script';
import { OPS } from '../../script';
import * as types from '../../types';

export function check(script: Buffer | Array<number | Buffer>): boolean {
  const buffer = bscript.compile(script);

  return (
    buffer.length === 58 &&
    buffer[0] === 0x21 &&
    types.ColorId(buffer.slice(1, 1 + types.COLOR_ID_LENGTH)) &&
    buffer[34] === OPS.OP_COLOR &&
    buffer[35] === OPS.OP_HASH160 &&
    buffer[36] === 0x14 &&
    buffer[57] === OPS.OP_EQUAL
  );
}
check.toJSON = (): string => {
  return 'colored scriptHash output';
};
