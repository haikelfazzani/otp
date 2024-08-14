export default function dec2hex(dec: number) {
  return dec.toString(16).padStart(2, '0');
}