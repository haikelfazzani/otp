import { HmacAlgorithm } from './types';

const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    let dummy = 0;
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
      dummy |= i;
    }
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

//  RFC 4226, Section 5.3
export function truncate(hmacResult: Uint8Array, digits: number): string {
  if (!Number.isInteger(digits) || digits < 1 || digits > 10) {
    throw new Error('Digits must be a positive integer between 1 and 10.');
  }

  if (hmacResult.length < 4) {
    throw new Error("HMAC result is too short");
  }

  const offset = hmacResult[hmacResult.length - 1] & 0x0f;
  if (offset > hmacResult.length - 4) {
    throw new Error("Calculated offset is out of bounds for the HMAC result");
  }

  const view = new DataView(hmacResult.buffer, hmacResult.byteOffset + offset, 4);
  const binaryCode = view.getUint32(0) & 0x7fffffff;
  const otp = binaryCode % (10 ** digits);
  return otp.toString().padStart(digits, '0');
}

// RFC 4648
export function base32ToBytes(key: string): Uint8Array {
  if (!key || typeof key !== 'string') {
    throw new Error("Secret key must be a non-empty string");
  }

  key = key.trim();

  if (key.length < 1) {
    throw new Error("Secret key must be a non-empty string");
  }

  const cleaned = key.replace(/\s+/g, '').replace(/=/g, '').toUpperCase();
  // RFC 4648 specifies that '0', '1', '8', and '9' are not valid Base32 characters
  if (!/^[A-Z2-7]+$/.test(cleaned)) {
    throw new Error('Invalid Base32 secret key.');
  }

  const byteLength = (cleaned.length * 5) >>> 3; // fast floor
  const out = new Uint8Array(byteLength);

  let bits = 0;
  let value = 0;
  let index = 0;

  for (let i = 0; i < cleaned.length; i++) {
    const charIndex = alphabet.indexOf(cleaned[i]);
    value = (value << 5) | charIndex;
    bits += 5;

    if (bits >= 8) {
      out[index++] = (value >>> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }
  return out;
}

// RFC 4648
export function bytesToBase32(bytes: Uint8Array): string {
  if (!bytes || bytes.length === 0) return '';

  const result: string[] = [];
  let bits = 0;
  let value = 0;

  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      result.push(alphabet[(value >>> (bits - 5)) & 31]);
      bits -= 5;
    }
  }

  if (bits > 0) {
    result.push(alphabet[(value << (5 - bits)) & 31]);
  }

  const output = result.join('');
  const paddingCount = (8 - (output.length % 8)) % 8;
  return output + '='.repeat(paddingCount);
}

export async function getCrypto(): Promise<Crypto> {
  // Browser and Deno
  if (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle) {
    return globalThis.crypto;
  }

  // Node.js fallback
  try {
    const { webcrypto } = await import('node:crypto');
    if (webcrypto?.subtle) {
      return webcrypto as unknown as Crypto;
    }
  } catch { }

  throw new Error('Web Crypto API (subtle) is not available in this environment');
}

export async function _generateHOTP(secretKey: string, counter: number | bigint, options: { digits: number; algorithm: HmacAlgorithm }): Promise<string> {
  const secretBytes = base32ToBytes(secretKey);
  const subtle = (await getCrypto()).subtle;
  const key = await subtle.importKey("raw", secretBytes, { name: "HMAC", hash: { name: options.algorithm } }, false, ["sign"]);

  // Use DataView and BigInt for RFC compliance.
  const msg = new Uint8Array(8);
  const view = new DataView(msg.buffer);
  view.setBigUint64(0, BigInt(counter), false); // false for big-endian

  const macBuf = await subtle.sign("HMAC", key, msg);
  return truncate(new Uint8Array(macBuf), options.digits);
}