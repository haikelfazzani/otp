import { HOTPOptions, HmacAlgorithm } from './types';
import { _generateHOTP } from './helpers';

export async function generateHOTP(secretKey: string, options?: HOTPOptions,): Promise<string> {
  if (!secretKey || typeof secretKey !== "string") {
    throw new Error("Secret key must be a non-empty string");
  }

  const merged = { algorithm: "SHA-1" as HmacAlgorithm, digits: 6, counter: 0, ...options, };

  if (typeof merged.counter !== "number" || merged.counter < 0 || merged.counter % 1 !== 0) {
    throw new Error("Counter must be a non-negative integer (not a float).");
  }

  if (!Number.isInteger(merged.digits) || merged.digits < 1 || merged.digits > 10) {
    throw new Error("Digits must be a positive integer between 1 and 10.");
  }

  return _generateHOTP(secretKey, merged.counter, {
    digits: merged.digits,
    algorithm: merged.algorithm,
  });
}