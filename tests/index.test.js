const { describe, expect, test } = require('@jest/globals');
const { generateTOTP, generateHOTP } = require('../dist/index.cjs');

describe('generate HOPT and TOPT code', () => {
  // tests from https://github.com/hectorm/otpauth/blob/master/test/test.mjs
  test('should generate code', async () => {
    const base32 = '6OWYXIW7QEYH34MFXCCXPZUBQDTIXBSX5GPKX4MSU2W6NHFNY2DOTEVK5OILVXN33GB6HN4QHHYLDN4AFTZZNH476KG3RAWESDUKZNHQW2KJLYMLTBHNJNPSTW33J4MAWWKNHPA'
    expect(await generateHOTP(base32, 1e10, 'SHA-1', 6)).toEqual("147664")
    expect(await generateTOTP(base32, { timestamp: 1451606400000, timeStep: 5 })).toEqual("757316")
  });

  test('should generate code', async () => {
    const base32 = '6OU2XBPNRSZTDXMS46VKJ4VCTC26ZBFJPHUK3LHRXSF27Y4LR7X37PPJVGU53LHCSOGMFPPDSWB7JB5YQLWLBF7TXS2JD4M7QSDNFL7QTSIJP4E7TKPUF4EUTSUPDNEZU7M3Z2MRWLZ3RA5I5OLLV4ULQOEQ'
    expect(await generateHOTP(base32, 1e10, 'SHA-512', 6)).toEqual("363952")
    expect(await generateTOTP(base32, { timestamp: 1451606400000, hash: 'SHA-512', digits: 6, timeStep: 15 })).toEqual("665593")
  });

  test('should generate code', async () => {
    const base32 = 'OR6O5BU2ZCD6PPEJ6OB2LKW5SXUZ7LJM6KS3ND7PX664ZOTWZOY6JJN24KX3N2FPVPT3BA7RXO6ISLJN26MOLF4O6GDK3AHTQ6S3XY4PW7UITDRA6OUZPCGVU7Z2HHE34KL2G'
    expect(await generateHOTP(base32, 1e10, 'SHA-1', 6)).toEqual("361593")
    expect(await generateTOTP(base32, { timestamp: 1451606400000 })).toEqual("329537")
  });

  test('should generate code', async () => {
    const base32 = "E3HL4LDW4KZL3ZV5RPWZPJPQT6KJLWFBFXQ2HJHSX2KZNSEA6KU3HERRY2J7HMNFTHYL5AVLE3BJJ2FPSHY3RKUU4SQIP4ESW64WERGXWXPLLUNL5K53DRVW4643A";
    expect(await generateHOTP(base32, 1e10, 'SHA-256', 6)).toEqual("789391")
    expect(await generateTOTP(base32, { timestamp: 1451606400000, hash: 'SHA-256', digits: 6, timeStep: 10 })).toEqual("043840")
  });

  test('should generate code', async () => {
    const base32 = "ZC6HDZFVQHH2TWMO6CV3ZPXRVGW3BRVH6G2JDOPCW255LBOWVHXIRC7AUSJMRAGWSXR33I7HWGE5PDOGVLHZXZVLXIQ7FA5MXQ3MTO7LQC4WDRMG6CV2LJO6WUZA";
    expect(await generateHOTP(base32, 1e10, 'SHA-1', 7)).toEqual("8319983")
    expect(await generateTOTP(base32, { timestamp: 1451606400000, digits: 7 })).toEqual("0565981")
  });
});

describe('generate TOPT code', () => {
  // tests from https://github.com/bellstrand/totp-generator/blob/master/src/index.spec.ts

  test('should generate correct code', async () => {
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: 0 })).toEqual("282760")
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: 1465324707000 })).toEqual("341128")
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: 1665644340000 - 1 })).toEqual("134996")
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: 1365324707000 })).toEqual("089029")
    expect(await generateTOTP("CI2FM6EQCI2FM6EQKU======", { timestamp: 1465324707000 })).toEqual("984195")
    expect(await generateTOTP("AAAAAAAAAAAAAAAA", { timestamp: 1400000000 })).toEqual("803661")
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { hash: "SHA-512", timestamp: 1465324707000 })).toEqual("093730")
    expect(await generateTOTP("3IS523AYRNFUE===", { hash: 'SHA-1', digits: 8, timestamp: 1634193300000 })).toEqual("97859470")
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: 12312354132421332222222222 })).toEqual("895896")
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: 0 })).toEqual("282760")
    expect(await generateTOTP('JBSWY3DPEHPK3PXP', { hash: 'SHA-1', timeStep: 30, digits: 6, timestamp: 1465324707000 })).toBe('341128');
  });

  test("should generate correct token", async () => {
    const start = 1665644340000
    const key = "JBSWY3DPEHPK3PXP";
    expect(await generateTOTP(key, { timestamp: start - 1 })).toEqual("134996")
    expect(await generateTOTP(key, { timestamp: start })).toEqual("886842")
    expect(await generateTOTP(key, { timestamp: start + 1 })).toEqual("886842")
    expect(await generateTOTP(key, { timestamp: start + 29999 })).toEqual("886842")
    expect(await generateTOTP(key, { timestamp: start + 30000 })).toEqual("421127")
    expect(await generateTOTP(key, { timestamp: start + 30001 })).toEqual("421127")
  });
})