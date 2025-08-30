// Zero dependencies Node 18+/Deno/Browser module for TOTP and HOTP generator based on RFC 6238 and RFC 4226
import { HmacAlgorithm, TOTPOptions, TOTPValidateOptions } from './types';
import { base32ToBytes, bytesToBase32, getCrypto, truncate, timingSafeEqual } from './helpers';

/**
 * Generates a cryptographically secure Base32 secret key.
 * @param length The desired length of the secret in bytes (default: 20).
 * @returns A Base32 encoded secret key.
 */
export async function generateSecret(length = 20): Promise<string> {
  const crypto = await getCrypto();
  const randomBytes = new Uint8Array(length);
  crypto.getRandomValues(randomBytes);
  return bytesToBase32(randomBytes);
}

/**
 * Generates an HMAC-based One-Time Password (HOTP).
 * @param secretKey The Base32 encoded secret key.
 * @param counter The counter value.
 * @param algorithm The HMAC hash algorithm to use (default: 'SHA-1').
 * @param digits The number of digits in the OTP (default: 6).
 * @returns A promise that resolves to the HOTP string.
 */
export async function generateHOTP(secretKey: string, counter: number, algorithm: HmacAlgorithm = 'SHA-1', digits = 6): Promise<string> {
  if (!Number.isInteger(counter) || counter < 0) {
    throw new Error("Counter must be a non-negative integer.");
  }
  if (!Number.isInteger(digits) || digits <= 0 || digits > 10) {
    throw new Error("Digits must be a positive integer between 1 and 10.");
  }

  // RFC 4226: 8-byte big-endian counter
  const msg = new Uint8Array(8);
  let tempCounter = counter;
  for (let i = 7; i >= 0; i--) {
    msg[i] = tempCounter & 0xff;
    tempCounter = Math.floor(tempCounter / 256);
  }

  const secretBytes = new Uint8Array(base32ToBytes(secretKey));
  const crypto = await getCrypto();
  const key = await crypto.subtle.importKey("raw", secretBytes, { name: "HMAC", hash: { name: algorithm } }, false, ["sign"]);
  const macBuf = await crypto.subtle.sign("HMAC", key, msg);
  const mac = new Uint8Array(macBuf);
  return truncate(mac, digits);
}

/**
 * Generates a Time-based One-Time Password (TOTP).
 * @param secretKey The Base32 encoded secret key.
 * @param options The options for TOTP generation.
 * @returns A promise that resolves to the TOTP string.
 */
export function generateTOTP(secretKey: string, options: TOTPOptions = {}): Promise<string> {
  const defaults = { algorithm: 'SHA-1' as HmacAlgorithm, period: 30, digits: 6, epoch: Date.now() };
  const merged = { ...defaults, ...options };

  if (!Number.isInteger(merged.period) || merged.period <= 0) {
    throw new Error("Period must be a positive integer.");
  }

  const counter = Math.floor((merged.epoch / 1000) / merged.period);
  return generateHOTP(secretKey, counter, merged.algorithm, merged.digits);
}

/**
 * Validates a TOTP token against a secret key, allowing for a window of tolerance.
 * @param token The OTP token to validate.
 * @param secretKey The Base32 encoded secret key.
 * @param options The options for TOTP validation, including the window.
 * @returns A promise that resolves to the delta of the matching window (`-1`, `0`, `1`, etc.) if valid, or `null` if invalid.
 */
export async function validate(token: string, secretKey: string, options: TOTPValidateOptions = {}): Promise<number | null> {
  const defaults = { algorithm: 'SHA-1' as HmacAlgorithm, period: 30, digits: 6, epoch: Date.now(), window: 1 };
  const merged = { ...defaults, ...options };

  if (typeof token !== 'string' || !/^\d+$/.test(token)) {
      return null;
  }
  
  const currentCounter = Math.floor((merged.epoch / 1000) / merged.period);

  for (let i = -merged.window; i <= merged.window; i++) {
      const counter = currentCounter + i;
      const expectedToken = await generateHOTP(secretKey, counter, merged.algorithm, merged.digits);

      if (timingSafeEqual(expectedToken, token)) {
          return i; // Return the delta of the successful window
      }
  }

  return null;
}