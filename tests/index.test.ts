import { describe, expect, test } from '@jest/globals';
import { generateTOTP, generateHOTP } from '../src/index';
import { TOTPOptions } from '../src/types';

describe('generate HOPT and TOPT: should generate correct token', () => {
  // tests from https://github.com/hectorm/otpauth/blob/master/test/test.mjs
  test('should generate code', async () => {
    const base32 = '6OWYXIW7QEYH34MFXCCXPZUBQDTIXBSX5GPKX4MSU2W6NHFNY2DOTEVK5OILVXN33GB6HN4QHHYLDN4AFTZZNH476KG3RAWESDUKZNHQW2KJLYMLTBHNJNPSTW33J4MAWWKNHPA'
    expect(await generateHOTP(base32, { counter: 1e10, algorithm: 'SHA-1', digits: 6 })).toEqual("147664")
    expect(await generateTOTP(base32, { epoch: 1451606400000, period: 5 })).toEqual("757316")
  });

  test('should generate code', async () => {
    const base32 = "ZC6HDZFVQHH2TWMO6CV3ZPXRVGW3BRVH6G2JDOPCW255LBOWVHXIRC7AUSJMRAGWSXR33I7HWGE5PDOGVLHZXZVLXIQ7FA5MXQ3MTO7LQC4WDRMG6CV2LJO6WUZA";
    expect(await generateHOTP(base32, { counter: 1e10, algorithm: 'SHA-1', digits: 7 })).toEqual("8319983")
    expect(await generateTOTP(base32, { epoch: 1451606400000, digits: 7 })).toEqual("0565981")
  });

  test('should generate code', async () => {
    const base32 = 'OR6O5BU2ZCD6PPEJ6OB2LKW5SXUZ7LJM6KS3ND7PX664ZOTWZOY6JJN24KX3N2FPVPT3BA7RXO6ISLJN26MOLF4O6GDK3AHTQ6S3XY4PW7UITDRA6OUZPCGVU7Z2HHE34KL2G'
    expect(await generateHOTP(base32, { counter: 1e10, algorithm: 'SHA-1', digits: 6 })).toEqual("361593")
    expect(await generateTOTP(base32, { epoch: 1451606400000 })).toEqual("329537")
  });

  test('should generate code', async () => {
    const base32 = '6OU2XBPNRSZTDXMS46VKJ4VCTC26ZBFJPHUK3LHRXSF27Y4LR7X37PPJVGU53LHCSOGMFPPDSWB7JB5YQLWLBF7TXS2JD4M7QSDNFL7QTSIJP4E7TKPUF4EUTSUPDNEZU7M3Z2MRWLZ3RA5I5OLLV4ULQOEQ'
    expect(await generateHOTP(base32, { counter: 1e10, algorithm: 'SHA-512', digits: 6 })).toEqual("363952")
    expect(await generateTOTP(base32, { epoch: 1451606400000, algorithm: 'SHA-512', digits: 6, period: 15 })).toEqual("665593")
  });

  test('should generate code', async () => {
    const base32 = "E3HL4LDW4KZL3ZV5RPWZPJPQT6KJLWFBFXQ2HJHSX2KZNSEA6KU3HERRY2J7HMNFTHYL5AVLE3BJJ2FPSHY3RKUU4SQIP4ESW64WERGXWXPLLUNL5K53DRVW4643A";
    expect(await generateHOTP(base32, { counter: 1e10, algorithm: 'SHA-256', digits: 6 })).toEqual("789391")
    expect(await generateTOTP(base32, { epoch: 1451606400000, algorithm: 'SHA-256', digits: 6, period: 10 })).toEqual("043840")
  });
});

describe('generateTOTP: should generate correct token', () => {
  // tests from https://github.com/bellstrand/totp-generator/blob/master/src/index.spec.ts
  test('should generate correct code', async () => {
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { epoch: 0 })).toEqual("282760")
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { epoch: 1465324707000 })).toEqual("341128")
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { epoch: 1665644340000 - 1 })).toEqual("134996")
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { epoch: 1365324707000 })).toEqual("089029")
    expect(await generateTOTP("CI2FM6EQCI2FM6EQKU======", { epoch: 1465324707000 })).toEqual("984195")
    expect(await generateTOTP("AAAAAAAAAAAAAAAA", { epoch: 1400000000 })).toEqual("803661")
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { algorithm: "SHA-512", epoch: 1465324707000 })).toEqual("093730")
    expect(await generateTOTP("3IS523AYRNFUE===", { algorithm: 'SHA-1', digits: 8, epoch: 1634193300000 })).toEqual("97859470")
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { epoch: 0 })).toEqual("282760")
    expect(await generateTOTP('JBSWY3DPEHPK3PXP', { algorithm: 'SHA-1', period: 30, digits: 6, epoch: 1465324707000 })).toBe('341128');
  });

  test("generateTOTP: should generate correct token", async () => {
    const start = 1665644340000
    const key = "JBSWY3DPEHPK3PXP";
    expect(await generateTOTP(key, { epoch: start - 1 })).toEqual("134996")
    expect(await generateTOTP(key, { epoch: start })).toEqual("886842")
    expect(await generateTOTP(key, { epoch: start + 1 })).toEqual("886842")
    expect(await generateTOTP(key, { epoch: start + 29999 })).toEqual("886842")
    expect(await generateTOTP(key, { epoch: start + 30000 })).toEqual("421127")
    expect(await generateTOTP(key, { epoch: start + 30001 })).toEqual("421127")
  });
})

describe('generateHOTP: Input validation and error handling', () => {
  const validKey = 'JBSWY3DPEHPK3PXP';

  test('generateHOTP: should throw on invalid counter', async () => {
    await expect(generateHOTP(validKey, { counter: -1 })).rejects.toThrow("Counter must be a non-negative integer.");
    await expect(generateHOTP(validKey, { counter: 1.5 })).rejects.toThrow("Counter must be a non-negative integer.");
  });

  test('generateHOTP: should throw on invalid digits', async () => {
    await expect(generateHOTP(validKey, { counter: 1, algorithm: 'SHA-1', digits: 0 })).rejects.toThrow("Digits must be a positive integer between 1 and 10.");
    await expect(generateHOTP(validKey, { counter: 1, algorithm: 'SHA-1', digits: 11 })).rejects.toThrow("Digits must be a positive integer between 1 and 10.");
    await expect(generateHOTP(validKey, { counter: 1, algorithm: 'SHA-1', digits: 5.5 })).rejects.toThrow("Digits must be a positive integer between 1 and 10.");
  });

  test('generateTOTP: should correctly handle base32 with whitespace and lowercase', async () => {
    const keyWithWhitespace = "JBS WY3 DPE HPK 3PX P";
    const keyWithLowercase = "jbswy3dpehpk3pxp";
    const expected = await generateTOTP(validKey, { epoch: 0 });
    expect(await generateTOTP(keyWithWhitespace, { epoch: 0 })).toEqual(expected);
    expect(await generateTOTP(keyWithLowercase, { epoch: 0 })).toEqual(expected);
  });
});



describe('More test cases', () => {
  test('should handle different time periods correctly', async () => {
    const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
    const options = { period: 30, digits: 8, algorithm: 'SHA-1', epoch: 59999999 } as TOTPOptions;
    const code = await generateTOTP(secret, options);
    expect(code).toEqual('64161339');
  });

  test('should handle different time periods correctly', async () => {
    const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
    const options = { period: 30, digits: 8, algorithm: 'SHA-1', epoch: 1111111111000 } as TOTPOptions;
    const code = await generateTOTP(secret, options);
    expect(code).toEqual('14050471');
  });
})