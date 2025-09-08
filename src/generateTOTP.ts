import { generateHOTP } from "./generateHOTP";
import { HmacAlgorithm, TOTPOptions } from "./types";

export function generateTOTP(secretKey: string, options: Partial<TOTPOptions> = {},): Promise<string> {
  if (!secretKey || typeof secretKey !== "string") {
    throw new Error("Secret key must be a non-empty string");
  }

  const merged = { algorithm: "SHA-1" as HmacAlgorithm, period: 30, digits: 6, epoch: Date.now(), ...options, };

  if (!Number.isInteger(merged.period) || merged.period <= 0) {
    throw new Error("Period must be a positive integer.");
  }

  const counter = Math.floor(merged.epoch / 1000 / merged.period);
  if (counter > Number.MAX_SAFE_INTEGER || counter < 0) {
    throw new Error("Counter value exceeds safe integer range");
  }

  return generateHOTP(secretKey, {
    counter,
    algorithm: merged.algorithm,
    digits: merged.digits,
  });
}