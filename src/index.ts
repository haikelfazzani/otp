import base32ToBytes from "./utils/base32ToBytes";
import dec2hex from "./utils/dec2hex";
import hexToBytes from "./utils/hexToBytes";
import leftpad from "./utils/leftpad";
import truncate from "./utils/truncate";

export async function generateHOTP(secretKey: string, counter: number, hash: string, digits: number = 6) {
  const key = await crypto.subtle.importKey('raw', base32ToBytes(secretKey), { name: 'HMAC', hash: { name: hash } }, false, ['sign']);
  const hmac = await crypto.subtle.sign('HMAC', key, hexToBytes(leftpad(dec2hex(counter), 16, '0')));
  return truncate(new Uint8Array(hmac), digits);
}

export async function generateTOTP(secretKey: string, options: { timeStep?: number, digits?: number, timestamp?: number, hash?: string } = {}) {

  const defaults = {
    hash: 'SHA-1',
    timeStep: 30,
    digits: 6,
    timestamp: Date.now(),
  };

  const mergedOptions = { ...defaults, ...options };
  const counter = Math.floor((mergedOptions.timestamp / 1000.0) / mergedOptions.timeStep);
  return generateHOTP(secretKey, counter, mergedOptions.hash, mergedOptions.digits);
}
