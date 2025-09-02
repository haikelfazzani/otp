import { HOTPOptions, HmacAlgorithm, TOTPOptions, TOTPValidateOptions } from './types';
import { _generateHOTP, bytesToBase32, getCrypto, timingSafeEqual } from './helpers';

export async function generateSecret(length = 160): Promise<string> {
  const crypto = await getCrypto();
  const randomBytes = new Uint8Array(length);
  crypto.getRandomValues(randomBytes);
  return bytesToBase32(randomBytes);
}

export async function generateHOTP(secretKey: string, options?: HOTPOptions): Promise<string> {
  if (!secretKey || typeof secretKey !== 'string') {
    throw new Error("Secret key must be a non-empty string");
  }

  const merged = { algorithm: 'SHA-1' as HmacAlgorithm, digits: 6, counter: 1, ...options };

  if (typeof merged.counter !== 'number' || merged.counter < 0 || merged.counter % 1 !== 0) {
    throw new Error("Counter must be a non-negative integer (not a float).");
  }

  if (!Number.isInteger(merged.digits) || merged.digits < 1 || merged.digits > 10) {
    throw new Error("Digits must be a positive integer between 1 and 10.");
  }

  return _generateHOTP(secretKey, merged.counter, {
    digits: merged.digits,
    algorithm: merged.algorithm
  });
}

export function generateTOTP(secretKey: string, options: Partial<TOTPOptions> = {}): Promise<string> {
  if (!secretKey || typeof secretKey !== 'string') {
    throw new Error("Secret key must be a non-empty string");
  }

  const merged = { algorithm: 'SHA-1' as HmacAlgorithm, period: 30, digits: 6, epoch: Date.now(), ...options };

  if (!Number.isInteger(merged.period) || merged.period <= 0) {
    throw new Error("Period must be a positive integer.");
  }

  const counter = Math.floor(merged.epoch / 1000 / merged.period);
  if (counter > Number.MAX_SAFE_INTEGER || counter < 0) {
    throw new Error("Counter value exceeds safe integer range");
  }

  return generateHOTP(secretKey, { counter, algorithm: merged.algorithm, digits: merged.digits });
}

/**
 * RFC 6238 Section 4.1
 * Validates a TOTP token against a secret key, allowing for a window of tolerance.
 * @param token The OTP token to validate.
 * @param secretKey The Base32 encoded secret key.
 * @param options The options for TOTP validation, including the window.
 * @returns A promise that resolves to:
 *   - `0`    if the token matches the current time period
 *   - `-1`   if the token matches the previous time period (client clock is behind)
 *   - `1`    if the token matches the next time period (client clock is ahead)
 *   - `null` if the token doesn't match any time period within the window
 */
export async function validate(token: string, secretKey: string, options: Partial<TOTPValidateOptions> = {}): Promise<number | null> {
  if (typeof token !== 'string' || !/^\d+$/.test(token)) return null;

  const merged = { algorithm: 'SHA-1' as HmacAlgorithm, period: 30, digits: 6, epoch: Date.now(), window: 1, ...options };
  if (token.length !== merged.digits) return null;

  const currentCounter = Math.floor((merged.epoch / 1000) / merged.period);

  for (let i = -merged.window; i <= merged.window; i++) {
    const counter = currentCounter + i;

    const expectedToken = await _generateHOTP(secretKey, counter, {
      digits: merged.digits,
      algorithm: merged.algorithm,
    });

    if (timingSafeEqual(expectedToken, token)) {
      return i;
    }
  }

  return null;
}
