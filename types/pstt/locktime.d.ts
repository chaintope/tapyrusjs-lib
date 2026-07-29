import { PsttInput } from './interfaces';
/**
 * The locktime of the transaction the given inputs describe.
 *
 * * With no required locktime, the fallback locktime is used (0 if omitted).
 * * Otherwise one kind must be acceptable to every input that requires one; an
 *   input specifying both kinds accepts either.
 * * The height-based kind wins when both are acceptable.
 * * The result is the maximum value of the chosen kind.
 *
 * @throws when no single kind is acceptable to every input that requires one.
 */
export declare function resolveLocktime(inputs: PsttInput[], fallbackLocktime?: number): number;
