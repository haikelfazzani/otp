export default function leftpad(str: string, len: number, pad: string) {
  return str.padStart(len, pad);
}