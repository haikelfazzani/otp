import { describe, expect, test } from '@jest/globals';
import { generateTOTP, generateSecret, validate } from '../src/index';

describe('validate', () => {
  let secret: string;

  beforeAll(async () => {
    secret = await generateSecret();
  });

  it('returns 0 for current valid token (window=1, default)', async () => {
    const token = await generateTOTP(secret);
    const result = await validate(token, secret);
    expect(result).toBe(0);
  });

  it('returns null for incorrect token', async () => {
    const result = await validate('123456', secret);
    expect(result).toBeNull();
  });

  it('returns -1 for previous period token (window=1)', async () => {
    const now = Date.now();
    const period = 30;
    const prevEpoch = now - period * 1000;
    const prevToken = await generateTOTP(secret, { epoch: prevEpoch });
    const result = await validate(prevToken, secret, { epoch: now, window: 1 });
    expect(result).toBe(-1);
  });

  it('returns 1 for next period token (window=1)', async () => {
    const now = Date.now();
    const period = 30;
    const nextEpoch = now + period * 1000;
    const nextToken = await generateTOTP(secret, { epoch: nextEpoch });
    const result = await validate(nextToken, secret, { epoch: now, window: 1 });
    expect(result).toBe(1);
  });

  it('returns null for token outside window', async () => {
    const now = Date.now();
    const period = 30;
    const farEpoch = now + period * 3000;
    const farToken = await generateTOTP(secret, { epoch: farEpoch });
    const result = await validate(farToken, secret, { epoch: now, window: 1 });
    expect(result).toBeNull();
  });

  it('returns 0 only for current period if window=0', async () => {
    const now = Date.now();
    const token = await generateTOTP(secret, { epoch: now });
    const prevToken = await generateTOTP(secret, { epoch: now - 30 * 1000 });
    const nextToken = await generateTOTP(secret, { epoch: now + 30 * 1000 });

    expect(await validate(token, secret, { epoch: now, window: 0 })).toBe(0);
    expect(await validate(prevToken, secret, { epoch: now, window: 0 })).toBeNull();
    expect(await validate(nextToken, secret, { epoch: now, window: 0 })).toBeNull();
  });

  it('returns null for tokens of incorrect length', async () => {
    const token = '12345'; // too short
    expect(await validate(token, secret)).toBeNull();
  });

  it('returns null for non-numeric tokens', async () => {
    expect(await validate('abcdef', secret)).toBeNull();
  });

  it('throws if window is negative', async () => {
    await expect(validate('123456', secret, { window: -1 })).rejects.toThrow();
  });
});

describe('validate: OTP Generation', () => {
  test('token matches the current time period', async () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const token = await generateTOTP(secret);
    expect(await validate(token, secret, { window: 1 })).toBe(0)
  });

  test('token matches the next time period', async () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const token = await generateTOTP(secret, { period: 30, epoch: Date.now() + 30000 });
    expect(await validate(token, secret, { window: 1 })).toBe(1)
  });

  test('token matches the previous time period', async () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const token = await generateTOTP(secret, { period: 30, epoch: Date.now() - 30000 });
    expect(await validate(token, secret, { window: 1 })).toBe(-1)
  });

  test('token doesn\'t match any time period within the window', async () => {
    expect(await validate("287082", 'JBSWY3DPEHPK3PXP', { window: 1 })).toBe(null)
  });

});