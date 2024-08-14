// rfc4226 section 5.4
export default function truncate(bytes: Uint8Array, digits: number) {
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