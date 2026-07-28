'use strict';
// "Determining the Locktime" of TIP-0174.
//
// Kept as a free function rather than a method so that the Pstt getter and the
// Constructor/Updater guards, which have to evaluate a hypothetical set of
// inputs, share one implementation.
Object.defineProperty(exports, '__esModule', { value: true });
exports.resolveLocktime = resolveLocktime;
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
function resolveLocktime(inputs, fallbackLocktime) {
  const times = [];
  const heights = [];
  let required = false;
  let timeOnly = false;
  let heightOnly = false;
  for (const input of inputs) {
    const time = input.requiredTimeLocktime;
    const height = input.requiredHeightLocktime;
    if (time === undefined && height === undefined) continue;
    required = true;
    if (time !== undefined) times.push(time);
    if (height !== undefined) heights.push(height);
    if (time !== undefined && height === undefined) timeOnly = true;
    if (height !== undefined && time === undefined) heightOnly = true;
  }
  if (!required) return fallbackLocktime || 0;
  if (timeOnly && heightOnly)
    throw new Error('No locktime kind is acceptable to every input');
  // The height-based locktime is chosen when both kinds are acceptable.
  return timeOnly ? Math.max(...times) : Math.max(...heights);
}
