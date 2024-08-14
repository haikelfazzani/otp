export default function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string');
  }

  return new Uint8Array(hex.match(/.{2}/g).map(byte => parseInt(byte, 16)));
}