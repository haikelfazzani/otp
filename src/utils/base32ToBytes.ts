export default function base32ToBytes(key: string) {
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