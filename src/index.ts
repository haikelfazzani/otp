import { options } from "./types";

export function base32ToBytes(key: string) {
  key = key.replace(/=\./g, '');
  const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  let bits = '';

  for (let i = 0; i < key.length; i++) {
    const ch = key[i].toUpperCase();
    const index = base32Chars.indexOf(ch);
    if (index === -1) {
      throw new Error('Invalid base32 character');
    }

    bits += index.toString(2).padStart(5, '0');
  }

  const bytes = [];

  for (let i = 0; i < bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2))
  }

  return new Uint8Array(bytes);
}

export function intToBytes(num: number) {
  const bytes = [];
  for (let i = 7; i >= 0; i--) {
    bytes[i] = num & 0xff;
    num = num >> 8;
  }
  return new Uint8Array(bytes);
}

// rfc4226 section 5.4
function truncate(bytes: Uint8Array, digits: number) {
  const offset = bytes[bytes.length - 1] & 0x0f;

  const code = ((bytes[offset] & 0x7f) << 24 |
    (bytes[offset + 1] & 0xff) << 16 |
    (bytes[offset + 2] & 0xff) << 8 |
    (bytes[offset + 3] & 0xff)) % Math.pow(10, digits);

  return code.toString().padStart(digits, '0');
}

export async function generateHOPT(secretKey: string, counter: number, hash: string, digits: number) {
  const key = await crypto.subtle.importKey(
    'raw',
    base32ToBytes(secretKey),
    { name: 'HMAC', hash: { name: hash } },
    false,
    ['sign']
  );
  const hmac = await crypto.subtle.sign('HMAC', key, intToBytes(counter));
  return truncate(new Uint8Array(hmac), digits);
}

export async function generateTOPT(secretKey: string, ops: options) {

  const options = {
    hash: 'sha-1',
    timeStep: 30,
    digits: 6,
    timestamp: Date.now(),
    ...ops
  }

  const counter = Math.floor((options.timestamp / 1000.0) / options.timeStep);
  return generateHOPT(secretKey, counter, options.hash, options.digits);
}
