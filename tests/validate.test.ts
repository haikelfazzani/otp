import { describe, expect, test } from '@jest/globals';
import { generateTOTP, validate } from '../src/index';

describe('OTP Generation', () => {
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