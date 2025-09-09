import { base32ToBytes } from './base32';
import { HmacAlgorithm } from './types';

/**
 * Timing-safe string comparison. Prevents timing attacks.
 * Use Node's crypto.timingSafeEqual if available for buffers.
 */
export function timingEqual(a: string, b: string): boolean {
  // Compare lengths first, but process both fully to mitigate timing leaks
  let result = a.length === b.length ? 0 : 1;
  const maxLen = Math.max(a.length, b.length);

  for (let i = 0; i < maxLen; i++) {
    result |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }

  return result === 0;
}

//  RFC 4226, Section 5.3
const RFC_4226_OFFSET_MASK = 0x0f;
const RFC_4226_TRUNCATE_MASK = 0x7fffffff;

export function truncate(hmacResult: Uint8Array, digits: number): string {
  if (!Number.isInteger(digits) || digits < 1 || digits > 10) {
    throw new Error('Digits must be a positive integer between 1 and 10.');
  }

  if (hmacResult.length < 4) {
    throw new Error("HMAC result is too short");
  }

  const offset = hmacResult[hmacResult.length - 1] & RFC_4226_OFFSET_MASK;
  if (offset > hmacResult.length - 4) {
    throw new Error("Calculated offset is out of bounds for the HMAC result");
  }

  let binaryCode: number;
  try {
    const view = new DataView(hmacResult.buffer, hmacResult.byteOffset + offset, 4);
    binaryCode = view.getUint32(0) & RFC_4226_TRUNCATE_MASK;
  } catch (err) {
    throw new Error("Failed to read truncated code: " + err.message);
  }
  const otp = binaryCode % (10 ** digits);
  return otp.toString().padStart(digits, '0');
}

export async function _generateHOTP(
  secretKey: string,
  counter: number | bigint,
  options: { digits: number; algorithm: HmacAlgorithm }
): Promise<string> {
  const secretBytes = base32ToBytes(secretKey);
  const key = await (await getCrypto()).subtle.importKey(
    "raw",
    secretBytes as BufferSource, // Uint8Array is BufferSource
    { name: "HMAC", hash: { name: options.algorithm } },
    false,
    ["sign"]
  );

  const msg = new Uint8Array(8);
  const view = new DataView(msg.buffer);
  view.setBigUint64(0, BigInt(counter), false);

  const macBuf = await (await getCrypto()).subtle.sign("HMAC", key, msg);
  return truncate(new Uint8Array(macBuf), options.digits);
}

/**
 * Cross-platform WebCrypto API getter.
 * Supports browser, Deno, and Node.js (via node:crypto webcrypto).
 * Caches the result for performance.
 */
let cachedCrypto: Crypto | null = null;

export async function getCrypto(): Promise<Crypto> {
  if (cachedCrypto) return cachedCrypto;
  // Browser/Deno
  if (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle) {
    cachedCrypto = globalThis.crypto;
    return cachedCrypto;
  }
  // Node.js fallback
  try {
    const { webcrypto } = await import('node:crypto');
    if (webcrypto?.subtle) {
      cachedCrypto = webcrypto as unknown as Crypto;
      return cachedCrypto;
    }
  } catch { }
  throw new Error('Web Crypto API (subtle) is not available in this environment');
}