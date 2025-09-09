import { bytesToBase32 } from './base32';
import { _generateHOTP, getCrypto } from './helpers';

export async function generateSecret(length = 160): Promise<string> {
  if (!Number.isInteger(length) || length < 1 || length > 1024) {
    throw new Error("Length must be a positive integer between 1 and 1024");
  }
  const crypto = await getCrypto();
  const randomBytes = new Uint8Array(length);
  crypto.getRandomValues(randomBytes);
  return bytesToBase32(randomBytes);
}
