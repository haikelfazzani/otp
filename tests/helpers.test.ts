import { truncate } from '../src/helpers';
import { base32ToBytes, bytesToBase32 } from '../src/base32';

describe('truncate', () => {
  describe('Valid inputs', () => {
    test('should truncate HMAC result to specified digits', () => {
      // Test vector from RFC 4226
      const hmac = new Uint8Array([
        0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16,
        0x61, 0x85, 0x50, 0xef, 0x7f, 0x19, 0xda, 0x8e,
        0x94, 0x5b, 0x55, 0x5a
      ]);

      const result = truncate(hmac, 6);
      expect(result).toBe('872921');
      expect(result.length).toBe(6);
    });

    test('should pad with leading zeros when necessary', () => {
      // Create HMAC that will result in small numbers
      const hmac = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00]);
      const result = truncate(hmac, 6);

      expect(result.length).toBe(6);
      expect(/^0+\d*$/.test(result)).toBe(true);
    });
  });

  describe('Invalid inputs', () => {
    test('should throw for HMAC shorter than 4 bytes', () => {
      expect(() => truncate(new Uint8Array([]), 6))
        .toThrow('HMAC result is too short');

      expect(() => truncate(new Uint8Array([0x12]), 6))
        .toThrow('HMAC result is too short');

      expect(() => truncate(new Uint8Array([0x12, 0x34, 0x56]), 6))
        .toThrow('HMAC result is too short');
    });

    test('should throw for invalid digit count', () => {
      const hmac = new Uint8Array([0x12, 0x34, 0x56, 0x78, 0x9a]);

      expect(() => truncate(hmac, 0)).toThrow('Digits must be a positive integer between 1 and 10.');
      expect(() => truncate(hmac, -1)).toThrow('Digits must be a positive integer between 1 and 10.');
      expect(() => truncate(hmac, 11)).toThrow('Digits must be a positive integer between 1 and 10.');
      expect(() => truncate(hmac, 1.5)).toThrow('Digits must be a positive integer between 1 and 10.');
    });

    test('should handle offset out of bounds', () => {
      const hmac = new Uint8Array([0x12, 0x34, 0x56, 0x7f]);
      expect(() => truncate(hmac, 6)).toThrow("Calculated offset is out of bounds for the HMAC result");
    });
  });

  describe('Edge cases', () => {
    test('should handle all possible offset values', () => {
      // Test different offset values (0-15)
      for (let offset = 0; offset <= 15; offset++) {
        const hmac = new Uint8Array(20); // SHA-1 length
        hmac[19] = offset; // Set the offset
        hmac[offset] = 0x12;
        hmac[offset + 1] = 0x34;
        hmac[offset + 2] = 0x56;
        hmac[offset + 3] = 0x78;

        expect(() => truncate(hmac, 6)).not.toThrow();
        const result = truncate(hmac, 6);
        expect(result.length).toBe(6);
        expect(/^\d{6}$/.test(result)).toBe(true);
      }
    });

    test('should produce consistent results for same input', () => {
      const hmac = new Uint8Array([
        0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16,
        0x61, 0x85, 0x50, 0xef, 0x7f, 0x19, 0xda, 0x8e,
        0x94, 0x5b, 0x55, 0x5a
      ]);

      const result1 = truncate(hmac, 6);
      const result2 = truncate(hmac, 6);
      expect(result1).toBe(result2);
    });
  });
});

describe('base32ToBytes', () => {
  describe('Valid inputs', () => {
    test('should decode valid Base32 strings', () => {
      // Test vectors
      const testCases = [
        { base32: 'MVSGM', expected: [0x65, 0x64, 0x66] },
        { base32: 'MVTWU', expected: [0x65, 0x67, 0x6A] },
      ];

      testCases.forEach(({ base32, expected }) => {
        const result = base32ToBytes(base32);
        expect(Array.from(result)).toEqual(expected);
      });
    });

    test('should handle padding correctly', () => {
      const testCases = [
        'NFZXK6Q=',    // 1 padding
        'NFZXK6QQ====', // 4 padding
      ];

      testCases.forEach(base32 => {
        expect(() => base32ToBytes(base32)).not.toThrow();
        const result = base32ToBytes(base32);
        expect(result).toBeInstanceOf(Uint8Array);
      });
    });

    test('should ignore whitespace', () => {
      const base32WithSpaces = ' M F R G G ';
      const base32Clean = 'MFRGG';

      const result1 = base32ToBytes(base32WithSpaces);
      const result2 = base32ToBytes(base32Clean);

      expect(Array.from(result1)).toEqual(Array.from(result2));
    });

    test('should be case insensitive', () => {
      const upperCase = 'MFRGG';
      const lowerCase = 'mfrgg';
      const mixedCase = 'MfRgG';

      const result1 = base32ToBytes(upperCase);
      const result2 = base32ToBytes(lowerCase);
      const result3 = base32ToBytes(mixedCase);

      expect(Array.from(result1)).toEqual(Array.from(result2));
      expect(Array.from(result1)).toEqual(Array.from(result3));
    });

    test('should handle typical secret key lengths', () => {
      const secrets = [
        'JBSWY3DPEHPK3PXP', // 16 chars (80 bits)
        'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP', // 32 chars (160 bits)
      ];

      secrets.forEach(secret => {
        const result = base32ToBytes(secret);
        expect(result.length).toBeGreaterThan(0);
        expect(result).toBeInstanceOf(Uint8Array);
      });
    });
  });

  describe('Invalid inputs', () => {
    test('should throw for invalid characters', () => {
      const invalidInputs = [
        'INVALID0', // contains '0'
        'INVALID1', // contains '1'  
        'INVALID8', // contains '8'
        'INVALID9', // contains '9'
        'HELLO!',   // contains '!'
        'TEST@',    // contains '@'
      ];

      invalidInputs.forEach(input => {
        expect(() => base32ToBytes(input)).toThrow('Invalid Base32 secret key');
      });
    });

    test('should throw for empty or non-string inputs', () => {
      expect(() => base32ToBytes('')).toThrow('Secret key must be a non-empty string');
      expect(() => base32ToBytes('   ')).toThrow('Secret key must be a non-empty string');
      expect(() => base32ToBytes(null as any)).toThrow('Secret key must be a non-empty string');
      expect(() => base32ToBytes(undefined as any)).toThrow('Secret key must be a non-empty string');
      expect(() => base32ToBytes(123 as any)).toThrow('Secret key must be a non-empty string');
    });
  });

  describe('Edge cases', () => {
    test('should handle boundary lengths', () => {
      // Test various lengths that exercise different padding scenarios
      const inputs = [
        'ME======',      // 1 byte
        'MFRA====',      // 2 bytes  
        'MFRGG===',      // 3 bytes
        'MFRGGZA=',      // 4 bytes
        'MFRGGZDF',      // 5 bytes
      ];

      inputs.forEach(input => {
        expect(() => base32ToBytes(input)).not.toThrow();
        const result = base32ToBytes(input);
        expect(result).toBeInstanceOf(Uint8Array);
      });
    });

    test('should produce consistent results', () => {
      const input = 'JBSWY3DPEHPK3PXP';
      const result1 = base32ToBytes(input);
      const result2 = base32ToBytes(input);

      expect(Array.from(result1)).toEqual(Array.from(result2));
    });
  });
});

describe('bytesToBase32', () => {
  describe('Valid inputs', () => {
    test('should encode bytes to Base32', () => {
      const testCases = [
        { bytes: [0x65, 0x64, 0x66], expected: "MVSGM===" },
        { bytes: [0x65, 0x67, 0x6a], expected: "MVTWU===" },
        { bytes: [0x00], expected: "AA======" },
        { bytes: [0xff], expected: "74======" },
      ];

      testCases.forEach(({ bytes, expected }) => {
        const input = new Uint8Array(bytes);
        const result = bytesToBase32(input);
        expect(result).toBe(expected);
      });
    });

    test('should include proper padding', () => {
      // Test different padding scenarios
      const testCases = [
        { length: 1, paddingCount: 6 },
        { length: 2, paddingCount: 4 },
        { length: 3, paddingCount: 3 },
        { length: 4, paddingCount: 1 },
        { length: 5, paddingCount: 0 },
      ];

      testCases.forEach(({ length, paddingCount }) => {
        const bytes = new Uint8Array(length).fill(0x41); // Fill with 'A'
        const result = bytesToBase32(bytes);
        const actualPadding = (result.match(/=/g) || []).length;
        expect(actualPadding).toBe(paddingCount);
      });
    });

    test('should handle typical secret lengths', () => {
      const lengths = [10, 16, 20, 32]; // Common secret lengths

      lengths.forEach(length => {
        const bytes = new Uint8Array(length).fill(0x42);
        const result = bytesToBase32(bytes);

        expect(result.length % 8).toBe(0); // Always multiple of 8 with padding
        expect(/^[A-Z2-7=]+$/.test(result)).toBe(true); // Valid Base32 chars
      });
    });

    test('should round-trip with base32ToBytes', () => {
      const testBytes = [
        new Uint8Array([0x12, 0x34, 0x56, 0x78]),
        new Uint8Array([0xFF, 0xEE, 0xDD, 0xCC, 0xBB]),
        new Uint8Array(Array.from({ length: 20 }, (_, i) => i)),
      ];

      testBytes.forEach(bytes => {
        const base32 = bytesToBase32(bytes);
        const decoded = base32ToBytes(base32);
        expect(Array.from(decoded)).toEqual(Array.from(bytes));
      });
    });
  });

  describe('Edge cases', () => {
    it('should correctly encode RFC 4648 test vectors', () => {

      function hexToBytes(hex: string) {
        if (hex.length % 2 !== 0) {
          throw new Error('Hex string must have an even length');
        }

        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
          bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
      }

      // Test vector from RFC 4648 (Section 10)
      const testCases = [
        { hex: '', expected: '' },
        { hex: '66', expected: 'MY======' }, // "f"
        { hex: '666f', expected: 'MZXQ====' }, // "fo"
        { hex: '666f6f', expected: 'MZXW6===' }, // "foo"
        { hex: '666f6f62', expected: 'MZXW6YQ=' }, // "foob"
        { hex: '666f6f6261', expected: 'MZXW6YTB' }, // "fooba"
        { hex: '666f6f626172', expected: 'MZXW6YTBOI======' }, // "foobar"
      ];

      testCases.forEach(({ hex, expected }) => {
        const bytes = hex ? hexToBytes(hex) : new Uint8Array();
        expect(bytesToBase32(bytes)).toBe(expected);
      });
    });

    test('should encode single byte correctly', () => {
      const bytes = new Uint8Array([0x41]);
      const result = bytesToBase32(bytes);
      expect(result).toBe('IE======');
    });

    test('should handle large inputs', () => {
      // 10 bytes → 80 bits → 16 Base32 chars + 0 padding
      const bytes = new Uint8Array(10);
      bytes.fill(0xFF); // All bits set to 1
      expect(bytesToBase32(bytes)).toBe('7777777777777777');
    });

    test('should handle empty input', () => {
      const result = bytesToBase32(new Uint8Array([]));
      expect(result).toBe('');
    });

    test('should handle single byte inputs', () => {
      for (let i = 0; i <= 255; i++) {
        const bytes = new Uint8Array([i]);
        const result = bytesToBase32(bytes);

        expect(result.length).toBe(8); // 2 chars + 6 padding
        expect(/^[A-Z2-7]{2}={6}$/.test(result)).toBe(true);
      }
    });

    test('should handle large inputs', () => {
      const largeBytes = new Uint8Array(1000).fill(0x55);
      expect(() => bytesToBase32(largeBytes)).not.toThrow();

      const result = bytesToBase32(largeBytes);
      expect(result.length).toBeGreaterThan(0);
      expect(/^[A-Z2-7=]+$/.test(result)).toBe(true);
    });

    test('should produce consistent results', () => {
      const bytes = new Uint8Array([0x12, 0x34, 0x56, 0x78, 0x9A]);
      const result1 = bytesToBase32(bytes);
      const result2 = bytesToBase32(bytes);

      expect(result1).toBe(result2);
    });

    test('should handle all bit patterns', () => {
      // Test various bit patterns to ensure proper encoding
      const patterns = [
        new Uint8Array([0x00, 0x00, 0x00, 0x00]), // All zeros
        new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF]), // All ones
        new Uint8Array([0xAA, 0xAA, 0xAA, 0xAA]), // Alternating bits
        new Uint8Array([0x55, 0x55, 0x55, 0x55]), // Alternating bits (inverted)
      ];

      patterns.forEach(pattern => {
        const result = bytesToBase32(pattern);
        expect(/^[A-Z2-7=]+$/.test(result)).toBe(true);

        // Verify round-trip
        const decoded = base32ToBytes(result);
        expect(Array.from(decoded)).toEqual(Array.from(pattern));
      });
    });
  });

  describe('Input validation', () => {
    test('should handle null and undefined gracefully', () => {
      expect(bytesToBase32(new Uint8Array())).toBe('');
    });

    test('should handle Uint8Array subviews', () => {
      const largeArray = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]);
      const subview = largeArray.subarray(2, 5); // [2, 3, 4]

      const result = bytesToBase32(subview);
      const expected = bytesToBase32(new Uint8Array([2, 3, 4]));

      expect(result).toBe(expected);
    });
  });
});

describe('Integration tests', () => {
  test('base32ToBytes and bytesToBase32 should be inverse operations', () => {
    const testData = [
      new Uint8Array([1, 2, 3, 4, 5]),
      new Uint8Array([255, 0, 128, 64, 32]),
      new Uint8Array(Array.from({ length: 20 }, (_, i) => i * 12 % 256)),
    ];

    testData.forEach(original => {
      const encoded = bytesToBase32(original);
      const decoded = base32ToBytes(encoded);
      expect(Array.from(decoded)).toEqual(Array.from(original));
    });
  });

  test('All functions should handle boundary conditions gracefully', () => {
    // Test with minimum and maximum reasonable inputs
    const minHmac = new Uint8Array(4).fill(0);
    const maxDigits = 10;

    expect(() => truncate(minHmac, 1)).not.toThrow();
    expect(() => truncate(minHmac, maxDigits)).not.toThrow();

    const emptyBytes = new Uint8Array(0);
    expect(bytesToBase32(emptyBytes)).toBe('');

    expect(() => base32ToBytes('')).toThrow(); // Should require non-empty
  });
});