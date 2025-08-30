export type HmacAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';

export type TOTPOptions = {
  algorithm?: HmacAlgorithm;
  period?: number;      // seconds, default: 30
  digits?: number;      // default: 6
  epoch?: number;       // ms, default: Date.now()
};

export type TOTPValidateOptions = TOTPOptions & {
  window?: number;
};