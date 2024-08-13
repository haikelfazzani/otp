const { describe, expect, test } = require('@jest/globals');
const { generateTOTP, generateHOTP } = require('../dist/index.cjs');

// tests by https://github.com/bellstrand/totp-generator/blob/master/src/index.spec.ts

describe('generate TOPT code', () => {

  test('should generate code', async () => {
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: 0 })).toEqual("282760")
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: 1465324707000 })).toEqual("341128")
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: 1665644340000 - 1 })).toEqual("134996")
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: 1365324707000 })).toEqual("089029")
    expect(await generateTOTP("CI2FM6EQCI2FM6EQKU======", { timestamp: 1465324707000 })).toEqual("984195")
    expect(await generateTOTP("AAAAAAAAAAAAAAAA", { timestamp: 1400000000 })).toEqual("803661")
  });
});

describe('generateTOTP', () => {
  it('should allow overriding default options', async () => {
    const options = { hash: 'SHA-1', timeStep: 30, digits: 6, timestamp: 1465324707000 };
    const totp = await generateTOTP('JBSWY3DPEHPK3PXP', options);
    expect(totp).toBe('341128');
  });

  it("should generate SHA-512-based token with date now = 2016", async () => {
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { hash: "SHA-512", timestamp: 1465324707000 })).toEqual("093730")
  });

  it("should generate token with timestamp from options", async () => {
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: 1465324707000 })).toEqual("341128")
  });

  it("should return all values when values is less then digits", async () => {
    const otp = await generateTOTP("3IS523AYRNFUE===", { hash: 'SHA-1', digits: 8, timestamp: 1634193300000 })
    expect(otp).toEqual("97859470")
  })

  test("should trigger leftpad fix", async () => {
    const otp = await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: 12312354132421332222222222 })
    expect(otp).toEqual("895896")
  });

  test("should generate correct token", async () => {
    const start = 1665644340000
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: start - 1 })).toEqual("134996")
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: start })).toEqual("886842")
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: start + 1 })).toEqual("886842")
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: start + 29999 })).toEqual("886842")
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: start + 30000 })).toEqual("421127")
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: start + 30001 })).toEqual("421127")
  });

  test("should generate correct token", async () => {
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: 0 })).toEqual("282760")
  });

})