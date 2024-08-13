import { options } from "./types";

function base32ToBytes(key: string) {
  key = key.trim().replace(/=/g, '');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const byteLength = Math.floor(key.length * 5 / 8);
  const uint8Array = new Uint8Array(byteLength);
  let value = 0;
  let bits = 0;
  let index = 0;

  for (let i = 0; i < key.length; i++) {
    const charIndex = alphabet.indexOf(key[i].toUpperCase());
    if (charIndex === -1) throw new Error('Invalid base32 character: ' + key[i]);

    value = (value * 32) + charIndex;
    bits += 5;

    while (bits >= 8) {
      uint8Array[index++] = Math.floor(value / Math.pow(2, bits - 8));
      value %= Math.pow(2, bits - 8);
      bits -= 8;
    }
  }

  return uint8Array;
};

function leftpad(str: string, len: number, pad: string) {
  if (len + 1 >= str.length) {
    str = Array(len + 1 - str.length).join(pad) + str
  }
  return str
}

function dec2hex(dec: number) {
  return (dec < 15.5 ? "0" : "") + Math.round(dec).toString(16)
}

function hexToBytes(hex: string) {
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

// rfc4226 section 5.4
function truncate(bytes: Uint8Array, digits: number) {
  if (digits <= 0 || !Number.isInteger(digits)) {
    throw new Error("Digits must be a positive integer.");
  }

  const offset = bytes[bytes.length - 1] & 0x0f;

  const code =
    ((bytes[offset] & 0x7f) << 24) |
    ((bytes[offset + 1] & 0xff) << 16) |
    ((bytes[offset + 2] & 0xff) << 8) |
    (bytes[offset + 3] & 0xff);

  const divisor = Math.pow(10, digits);
  const truncatedCode = code % divisor;

  return truncatedCode.toString().padStart(digits, '0');
}

export async function generateHOTP(secretKey: string, counter: number, hash: string, digits: number) {
  const key = await crypto.subtle.importKey('raw', base32ToBytes(secretKey), { name: 'HMAC', hash: { name: hash } }, false, ['sign']);
  const hmac = await crypto.subtle.sign('HMAC', key, hexToBytes(leftpad(dec2hex(counter), 16, '0')));
  return truncate(new Uint8Array(hmac), digits);
}

export async function generateTOTP(secretKey: string, ops: options) {

  const options = {
    hash: 'sha-1',
    timeStep: 30,
    digits: 6,
    timestamp: Date.now(),
    ...ops
  }

  const counter = Math.floor((options.timestamp / 1000.0) / options.timeStep);
  return generateHOTP(secretKey, counter, options.hash, options.digits);
}
