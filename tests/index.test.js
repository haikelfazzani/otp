const { describe, expect, test } = require('@jest/globals');
const { generateTOTP } = require('../dist/index.cjs');

describe('generate TOPT code', () => {

  test('should generate code', async () => {

    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: 0 })).toEqual("282760")
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: 1465324707000 })).toEqual("341128")
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: 1665644340000 - 1 })).toEqual("134996")
    expect(await generateTOTP("JBSWY3DPEHPK3PXP", { timestamp: 1365324707000 })).toEqual("089029")
    expect(await generateTOTP("CI2FM6EQCI2FM6EQKU======", { timestamp: 1465324707000 })).toEqual("984195")
    expect(await generateTOTP("AAAAAAAAAAAAAAAA", { timestamp: 1400000000 })).toEqual("803661")

  });

  // test('should throw error', async () => {
  //   expect(await generateTOTP("JBSWY3DPEHPK3!@#")).toThrow("Invalid base32 character")
  // });
});

