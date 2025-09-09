import { _generateHOTP, timingEqual } from "./helpers";
import { HmacAlgorithm, TOTPValidateOptions } from "./types";

/**
 * Validates a TOTP token against a secret key, allowing for a window of tolerance.
 *
 * @param token The OTP token to validate.
 * @param secretKey The Base32 encoded secret key.
 * @param options Options for TOTP validation.
 *   - algorithm: HMAC algorithm (default "SHA-1")
 *   - period: time step in seconds (default 30)
 *   - digits: number of digits in token (default 6)
 *   - epoch: time in ms (default Date.now())
 *   - window: number of time steps before/after to allow (default 1)
 *
 * @returns
 *   - `0`    if the token matches the current time period
 *   - `-1`   if the token matches the previous time period (client clock is behind)
 *   - `1`    if the token matches the next time period (client clock is ahead)
 *   - `null` if the token doesn't match any time period within the window
 *
 * @security
 *   - **window** parameter is critical for balancing security and usability:
 *     - `window = 0`: Maximum security (only current time step accepted). Recommended for high-security ops.
 *     - `window = 1`: Standard (accepts ±1 period). Good balance for most apps; tolerates up to ±period seconds drift.
 *     - `window ≥ 2`: Tolerant (for environments with poor time sync). Increases risk of replay attacks.
 *   - Always prefer the lowest window your use-case allows. For privileged or irreversible actions (transfers, password changes), set `window = 0`.
 *   - Ensure server and client clocks are synchronized (NTP recommended).
 *
 * @example
 * // Standard validation
 * validate(token, secret, {window: 1})
 *
 * // Strict validation, high security
 * validate(token, secret, {window: 0})
 */
export async function validate(token: string, secretKey: string, options: Partial<TOTPValidateOptions> = {},): Promise<number | null> {
  if (typeof token !== "string" || !/^\d+$/.test(token)) return null;

  const merged = {
    algorithm: "SHA-1" as HmacAlgorithm,
    period: 30,
    digits: 6,
    epoch: Date.now(),
    window: 1,
    ...options,
  };
  if (
    !Number.isInteger(merged.window) ||
    merged.window < 0 ||
    merged.window > 10
  ) {
    throw new Error(
      "Window must be a non-negative integer (recommended: 0-2).",
    );
  }
  if (token.length !== merged.digits) return null;

  const currentCounter = Math.floor(merged.epoch / 1000 / merged.period);

  for (let i = -merged.window; i <= merged.window; i++) {
    const counter = currentCounter + i;

    const expectedToken = await _generateHOTP(secretKey, counter, {
      digits: merged.digits,
      algorithm: merged.algorithm,
    });

    if (timingEqual(expectedToken, token)) {
      return i === 0 ? 0 : i;
    }
  }

  return null;
}
