import { describe, expect, test } from '@jest/globals';
import { generateTOTP, generateHOTP, validate } from '../src/index';
import { HOTPOptions } from '../src/index';

describe('OTP Generation', () => {
  describe('HOTP (HMAC-based One-Time Password)', () => {
    describe('Standard Test Vectors', () => {
      // Tests from https://github.com/hectorm/otpauth/blob/master/test/test.mjs
      test('should generate correct SHA-1 HOTP with 6 digits', async () => {
        const secret = '6OWYXIW7QEYH34MFXCCXPZUBQDTIXBSX5GPKX4MSU2W6NHFNY2DOTEVK5OILVXN33GB6HN4QHHYLDN4AFTZZNH476KG3RAWESDUKZNHQW2KJLYMLTBHNJNPSTW33J4MAWWKNHPA';
        const options: HOTPOptions = { counter: 1e10, algorithm: 'SHA-1', digits: 6 };
        await expect(generateHOTP(secret, options)).resolves.toBe('147664');
      });

      test('should generate correct SHA-1 HOTP with 7 digits', async () => {
        const secret = 'ZC6HDZFVQHH2TWMO6CV3ZPXRVGW3BRVH6G2JDOPCW255LBOWVHXIRC7AUSJMRAGWSXR33I7HWGE5PDOGVLHZXZVLXIQ7FA5MXQ3MTO7LQC4WDRMG6CV2LJO6WUZA';
        const options: HOTPOptions = { counter: 1e10, algorithm: 'SHA-1', digits: 7 };
        await expect(generateHOTP(secret, options)).resolves.toBe('8319983');
      });

      test('should generate correct SHA-512 HOTP', async () => {
        const secret = '6OU2XBPNRSZTDXMS46VKJ4VCTC26ZBFJPHUK3LHRXSF27Y4LR7X37PPJVGU53LHCSOGMFPPDSWB7JB5YQLWLBF7TXS2JD4M7QSDNFL7QTSIJP4E7TKPUF4EUTSUPDNEZU7M3Z2MRWLZ3RA5I5OLLV4ULQOEQ';
        const options: HOTPOptions = { counter: 1e10, algorithm: 'SHA-512', digits: 6 };
        await expect(generateHOTP(secret, options)).resolves.toBe('363952');
      });
    });

    describe('Input Validation', () => {
      const validSecret = 'JBSWY3DPEHPK3PXP';

      test('should throw on invalid counter (negative)', async () => {
        await expect(generateHOTP(validSecret, { counter: -1 })).rejects.toThrow('Counter must be a non-negative integer (not a float).');
      });

      test('should throw on invalid counter (non-integer)', async () => {
        await expect(generateHOTP(validSecret, { counter: 1.5 })).rejects.toThrow('Counter must be a non-negative integer (not a float).');
      });

      test('should throw on invalid digits (out of range)', async () => {
        await expect(generateHOTP(validSecret, { counter: 1, digits: 0 })).rejects.toThrow('Digits must be a positive integer between 1 and 10.');
        await expect(generateHOTP(validSecret, { counter: 1, digits: 11 })).rejects.toThrow('Digits must be a positive integer between 1 and 10.');
      });

      test('should throw on invalid digits (non-integer)', async () => {
        await expect(generateHOTP(validSecret, { counter: 1, digits: 5.5 })).rejects.toThrow('Digits must be a positive integer between 1 and 10.');
      });

      test('should throw on invalid algorithm', async () => {
        await expect(generateHOTP(validSecret, { counter: 1, algorithm: 'MD5' as any })).rejects.toThrow('Unrecognized algorithm name');
      });
    });
  });

  describe('TOTP (Time-based One-Time Password)', () => {
    describe('Standard Test Vectors', () => {
      // Tests from https://github.com/bellstrand/totp-generator/blob/master/src/index.spec.ts
      test('should generate correct codes for various epochs', async () => {
        const secret = 'JBSWY3DPEHPK3PXP';
        await expect(generateTOTP(secret, { epoch: 0 })).resolves.toBe('282760');
        await expect(generateTOTP(secret, { epoch: 1465324707000 })).resolves.toBe('341128');
        await expect(generateTOTP(secret, { epoch: 1665644340000 - 1 })).resolves.toBe('134996');
      });

      test('should handle different algorithms and parameters', async () => {
        const secret = 'JBSWY3DPEHPK3PXP';
        await expect(generateTOTP(secret, { algorithm: 'SHA-512', epoch: 1465324707000 })).resolves.toBe('093730');
        await expect(generateTOTP('3IS523AYRNFUE===', { algorithm: 'SHA-1', digits: 8, epoch: 1634193300000 })).resolves.toBe('97859470');
      });

      test('should handle different periods correctly', async () => {
        const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
        await expect(generateTOTP(secret, { period: 30, digits: 8, algorithm: 'SHA-1', epoch: 59999999 })).resolves.toBe('64161339');
        await expect(generateTOTP(secret, { period: 30, digits: 8, algorithm: 'SHA-1', epoch: 1111111111000 })).resolves.toBe('14050471');
      });
    });

    describe('Time Window Behavior', () => {
      test('should generate correct codes around period boundaries', async () => {
        const secret = 'JBSWY3DPEHPK3PXP';
        const start = 1665644340000;
        const token = await generateTOTP(secret, { epoch: start - 1 });

        expect(token).toBe('134996');
        await expect(generateTOTP(secret, { epoch: start })).resolves.toBe('886842');
        await expect(generateTOTP(secret, { epoch: start + 29999 })).resolves.toBe('886842');
        await expect(generateTOTP(secret, { epoch: start + 30000 })).resolves.toBe('421127');
        await expect(validate(token, secret, { epoch: start - 1 })).resolves.toBe(0);
      });
    });

    describe('Input Handling', () => {
      const validSecret = 'JBSWY3DPEHPK3PXP';

      test('should handle base32 with whitespace and lowercase', async () => {
        const keyWithWhitespace = "JBS WY3 DPE HPK 3PX P";
        const keyWithLowercase = "jbswy3dpehpk3pxp";
        const expected = await generateTOTP(validSecret, { epoch: 0 });

        await expect(generateTOTP(keyWithWhitespace, { epoch: 0 })).resolves.toBe(expected);
        await expect(generateTOTP(keyWithLowercase, { epoch: 0 })).resolves.toBe(expected);
      });

      test('should throw on invalid digits', async () => {
        await expect(generateTOTP(validSecret, { digits: 0 })).rejects.toThrow('Digits must be a positive integer between 1 and 10.');
        await expect(generateTOTP(validSecret, { digits: 11 })).rejects.toThrow('Digits must be a positive integer between 1 and 10.');
      });
    });
  });

  describe('Edge Cases', () => {
    test('should handle maximum digit value (10)', async () => {
      const secret = 'JBSWY3DPEHPK3PXP';
      const result = await generateTOTP(secret, { digits: 10, epoch: 0 });
      expect(result).toMatch(/^\d{10}$/);
    });

    test('should handle minimum digit value (1)', async () => {
      const secret = 'JBSWY3DPEHPK3PXP';
      const result = await generateTOTP(secret, { digits: 1, epoch: 0 });
      expect(result).toMatch(/^\d{1}$/);
    });

    test('should handle very large counter values', async () => {
      const secret = 'JBSWY3DPEHPK3PXP';
      const largeCounter = Number.MAX_SAFE_INTEGER - 1;
      await expect(generateHOTP(secret, { counter: largeCounter })).resolves.not.toThrow();
    });
  });
});