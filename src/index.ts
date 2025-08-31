// Node 18+/Deno/Browser TOTP and HOTP generator based on RFC 6238 and RFC 4226
import { HOTPOptions, HmacAlgorithm, TOTPOptions, TOTPValidateOptions } from './types';
import { base32ToBytes, bytesToBase32, getCrypto, truncate, timingSafeEqual } from './helpers';

export async function generateSecret(length = 20): Promise<string> {
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

  // RFC 4226: 8-byte big-endian counter
  const msg = new Uint8Array(8);

  // Convert number to 8-byte big-endian array without BigInt
  // Handle the full 64-bit range properly
  const high = Math.floor(merged.counter / 0x100000000); // Upper 32 bits
  const low = merged.counter % 0x100000000; // Lower 32 bits

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
  const subtle = (await getCrypto()).subtle;
  const key = await subtle.importKey("raw", secretBytes, { name: "HMAC", hash: { name: merged.algorithm } }, false, ["sign"]);
  const macBuf = await subtle.sign("HMAC", key, msg);
  return truncate(new Uint8Array(macBuf), merged.digits);
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

  const merged = { algorithm: 'SHA-1', period: 30, digits: 6, epoch: Date.now(), window: 1, ...options };
  if (token.length !== merged.digits) return null;

  const secretBytes = base32ToBytes(secretKey);
  const subtle = (await getCrypto()).subtle;
  const key = await subtle.importKey("raw", secretBytes, { name: "HMAC", hash: { name: merged.algorithm } }, false, ["sign"]);
  const currentCounter = Math.floor((merged.epoch / 1000) / merged.period);

  for (let i = -merged.window; i <= merged.window; i++) {
    const counter = currentCounter + i;
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

    const macBuf = await subtle.sign("HMAC", key, msg);
    const mac = new Uint8Array(macBuf);
    const expectedToken = truncate(mac, merged.digits);

    if (timingSafeEqual(expectedToken, token)) {
      return i;
    }
  }

  return null;
}