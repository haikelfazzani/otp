const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Decodes a Base32 string to Uint8Array (RFC 4648).
 * Throws if invalid characters are present.
 */
export function base32ToBytes(key: string): Uint8Array {
  if (!key || typeof key !== 'string') {
    throw new Error("Secret key must be a non-empty string");
  }

  const cleaned = key.trim().replace(/\s+/g, '').replace(/=/g, '').toUpperCase();
  if (cleaned.length < 1) {
    throw new Error("Secret key must be a non-empty string");
  }
  if (!/^[A-Z2-7]+$/.test(cleaned)) {
    throw new Error('Invalid Base32 secret key.');
  }

  const byteLength = (cleaned.length * 5) >>> 3;
  const out = new Uint8Array(byteLength);

  let bits = 0;
  let value = 0;
  let index = 0;

  for (let i = 0; i < cleaned.length; i++) {
    const charIndex = BASE32_ALPHABET.indexOf(cleaned[i]);
    if (charIndex === -1) throw new Error(`Invalid Base32 character: '${cleaned[i]}'`);
    value = (value << 5) | charIndex;
    bits += 5;

    if (bits >= 8) {
      out[index++] = (value >>> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }
  return out;
}


/**
 * Encodes Uint8Array to a Base32 string (RFC 4648).
 */
export function bytesToBase32(bytes: Uint8Array): string {
  if (!bytes || bytes.length === 0) return '';

  const result: string[] = [];
  let bits = 0;
  let value = 0;

  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      result.push(BASE32_ALPHABET[(value >>> (bits - 5)) & 31]);
      bits -= 5;
    }
  }

  if (bits > 0) {
    result.push(BASE32_ALPHABET[(value << (5 - bits)) & 31]);
  }

  const output = result.join('');
  const paddingCount = (8 - (output.length % 8)) % 8;
  return output + '='.repeat(paddingCount);
}