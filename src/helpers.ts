const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Compares two strings in a way that is resistant to timing attacks.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

export function truncate(bytes: Uint8Array, digits: number): string {
  if (!Number.isInteger(digits) || digits <= 0) {
    throw new Error("Digits must be a positive integer.");
  }
  if (!bytes || bytes.length < 4) {
    throw new Error("HMAC must be at least 4 bytes.");
  }

  const offset = bytes[bytes.length - 1] & 0x0f;
  if (offset + 3 >= bytes.length) {
    throw new Error("Invalid dynamic offset for truncation.");
  }

  const code =
    ((bytes[offset] & 0x7f) << 24) |
    ((bytes[offset + 1] & 0xff) << 16) |
    ((bytes[offset + 2] & 0xff) << 8) |
    (bytes[offset + 3] & 0xff);

  const divisor = 10 ** digits;
  return String(code % divisor).padStart(digits, '0');
}

export function base32ToBytes(key: string): Uint8Array {
  key = key.trim();
  if (!key || typeof key !== 'string') {
    throw new Error("Secret key must be a non-empty string");
  }

  const cleaned = key.replace(/\s+/g, '').replace(/=/g, '').toUpperCase();
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

export function bytesToBase32(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }

  return output;
}

export async function getCrypto(): Promise<Crypto> {
  const globalCrypto = (globalThis as any).crypto as Crypto | undefined;
  if (globalCrypto && globalCrypto.subtle) {
    return globalCrypto;
  }
  try {
    const { webcrypto } = await import('node:crypto');
    if (webcrypto && (webcrypto as any).subtle) {
      return webcrypto as unknown as Crypto;
    }
  } catch (e) {
    // Fall through to the error
  }
  throw new Error('Web Crypto API (subtle) is not available in this environment');
}