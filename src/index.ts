// Zero dependencies Node 18+/Deno/Browser module for TOTP and HOTP generator based on RFC 6238 and RFC 4226
import { HmacAlgorithm, TOTPOptions, TOTPValidateOptions } from './types';
import { base32ToBytes, bytesToBase32, getCrypto, truncate, timingSafeEqual } from './helpers';

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

  if (!secretKey || typeof secretKey !== 'string') {
    throw new Error("Secret key must be a non-empty string");
  }

  if (!Number.isInteger(counter) || counter < 0) throw new Error("Counter must be a non-negative integer.");

  if (!Number.isInteger(digits) || digits < 1 || digits > 10) {
    throw new Error("Digits must be a positive integer between 1 and 10.");
  }

  // RFC 4226: 8-byte big-endian counter
  const msg = new Uint8Array(8);

  // Convert number to 8-byte big-endian array without BigInt
  // Handle the full 64-bit range properly
  const high = Math.floor(counter / 0x100000000); // Upper 32 bits
  const low = counter % 0x100000000; // Lower 32 bits

  // Fill the 8-byte array in big-endian order
  msg[0] = (high >>> 24) & 0xff;
  msg[1] = (high >>> 16) & 0xff;
  msg[2] = (high >>> 8) & 0xff;
  msg[3] = high & 0xff;
  msg[4] = (low >>> 24) & 0xff;
  msg[5] = (low >>> 16) & 0xff;
  msg[6] = (low >>> 8) & 0xff;
  msg[7] = low & 0xff;

  const secretBytes = base32ToBytes(secretKey);
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
export function generateTOTP(secretKey: string, options: Partial<TOTPOptions> = {}): Promise<string> {
  if (!secretKey || typeof secretKey !== 'string') {
    throw new Error("Secret key must be a non-empty string");
  }

  const defaults = { algorithm: 'SHA-1' as HmacAlgorithm, period: 30, digits: 6, epoch: Date.now() };
  const merged = { ...defaults, ...options };

  if (!Number.isInteger(merged.period) || merged.period <= 0) {
    throw new Error("Period must be a positive integer.");
  }

  const counter = Math.floor(merged.epoch / 1000 / merged.period);
  if (counter > Number.MAX_SAFE_INTEGER || counter < 0) {
    throw new Error("Counter value exceeds safe integer range");
  }

  return generateHOTP(secretKey, counter, merged.algorithm, merged.digits);
}

/**
 * Validates a TOTP token against a secret key, allowing for a window of tolerance.
 * @param token The OTP token to validate.
 * @param secretKey The Base32 encoded secret key.
 * @param options The options for TOTP validation, including the window.
 * @returns A promise that resolves to the delta of the matching window (`-1`, `0`, `1`, etc.) if valid, or `null` if invalid.
 */
export async function validate(token: string, secretKey: string, options: Partial<TOTPValidateOptions> = {}): Promise<number | null> {
  const defaults = { algorithm: 'SHA-1' as HmacAlgorithm, period: 30, digits: 6, epoch: Date.now(), window: 1 };
  const merged = { ...defaults, ...options };

  if (typeof token !== 'string' || !/^\d+$/.test(token) || token.length !== merged.digits) {
    return null;
  }

  // Import key once for all validations
  const secretBytes = base32ToBytes(secretKey);
  const crypto = await getCrypto();
  const key = await crypto.subtle.importKey("raw", secretBytes, { name: "HMAC", hash: { name: merged.algorithm } }, false, ["sign"]);
  const currentCounter = Math.floor((merged.epoch / 1000) / merged.period);

  for (let i = -merged.window; i <= merged.window; i++) {
    const counter = currentCounter + i;

    // Inline HOTP generation without key re-import
    const msg = new Uint8Array(8);
    const high = Math.floor(counter / 0x100000000);
    const low = counter % 0x100000000;

    msg[0] = (high >>> 24) & 0xff;
    msg[1] = (high >>> 16) & 0xff;
    msg[2] = (high >>> 8) & 0xff;
    msg[3] = high & 0xff;
    msg[4] = (low >>> 24) & 0xff;
    msg[5] = (low >>> 16) & 0xff;
    msg[6] = (low >>> 8) & 0xff;
    msg[7] = low & 0xff;

    const macBuf = await crypto.subtle.sign("HMAC", key, msg);
    const mac = new Uint8Array(macBuf);
    const expectedToken = truncate(mac, merged.digits);

    if (timingSafeEqual(expectedToken, token)) {
      return i;
    }
  }

  return null;
}