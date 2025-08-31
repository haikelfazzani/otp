# One-Time Password (OTP) Generator

🔐 A zero-dependency, isomorphic TypeScript module for generating and validating
HOTP and TOTP codes, compliant with RFC 4226 and RFC 6238. 🗝️

---

<div align="center" style="width:100%; text-align:center; margin-bottom:20px;">
  <img src="https://badgen.net/bundlephobia/minzip/one-time-pass" alt="one-time-pass" />
  <img src="https://badgen.net/bundlephobia/dependency-count/one-time-pass" alt="one-time-pass" />
  <img src="https://badgen.net/npm/v/one-time-pass" alt="one-time-pass" />
  <img src="https://badgen.net/npm/dt/one-time-pass" alt="one-time-pass" />
  <img src="https://data.jsdelivr.com/v1/package/npm/one-time-pass/badge" alt="one-time-pass"/>
</div>

Try it out on JSFiddle:
[Live Demo](https://codepen.io/haikelfazzani/pen/pvjxdyp)

### ✨ Features

- **Zero Dependencies**: No external libraries needed. Works out-of-the-box.
- **Isomorphic**: Runs seamlessly in Node.js, Deno, Bun, and modern browsers.
- **Standard Compliant**: Strictly follows RFC 4226 (HOTP) and RFC 6238 (TOTP).
- **Secure Validation**: Includes a timing-safe validation function with a
  `window` to handle clock drift.
- **TypeScript Native**: Written in TypeScript with full type definitions
  included.

---

### 📦 Installation

```bash
npm install one-time-pass
```

---

Use the library directly in an HTML file via a CDN.

```html
<script
  src="https://cdn.jsdelivr.net/npm/one-time-pass/dist/index.umd.js"
></script>
<script>
  (async () => {
    // The library is available on the `window.otp` object
    const secret = await window.otp.generateSecret();
    console.log("Secret:", secret);

    const token = await window.otp.generateTOTP(secret);
    console.log("Token:", token);
  })();
</script>
```

---

### 💡 API Usage

The library provides a simple and modern async API.

#### **1. Generate a Secret Key**

First, generate a secure, Base32-encoded secret key for your user. This should
be stored safely.

```javascript
import { generateSecret } from "one-time-pass";

const secret = await generateSecret();
// Example Output: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
console.log("Your new secret is:", secret);
```

#### **2. Generate a TOTP (Time-Based OTP)**

Use the secret key to generate a time-based token.

```javascript
import { generateTOTP } from "one-time-pass";

const tokenWithOptions = await generateTOTP(secret, {
  algorithm: "SHA-1",
  digits: 6,
  period: 30, // 30 seconds
  epoch: Date.now(),
});
```

#### **3. Validate a TOTP**

Validate the token submitted by the user. The `window` option allows you to
accept tokens from adjacent time steps to account for clock drift.

```javascript
import { validate } from "one-time-pass";

const userToken = "287082"; // Token from user input

// Check the current, previous, and next time windows (window: 1)
const delta = await validate(userToken, secret, { window: 1 });

if (delta !== null) {
  console.log("✅ Token is valid!");
  console.log(`Matched with delta: ${delta}`); // Can be -1, 0, or 1
} else {
  console.log("❌ Token is invalid.");
}
```

#### **4. Generate an HOTP (Counter-Based OTP)**

You can also generate counter-based tokens. Ensure you securely store and
increment the counter for each use.

```javascript
import { generateHOTP } from "one-time-pass";
const hotpToken = await generateHOTP("secret", {
  counter: 1,
  algorithm: "SHA-1",
  digits: 6,
});
console.log("Your HOTP token is:", hotpToken);
```

---

### 🔧 API Reference

| Function         | Parameters                                                       | Returns                   | Description                                                   |
| ---------------- | ---------------------------------------------------------------- | ------------------------- | ------------------------------------------------------------- |
| `generateSecret` | `(length?: number)`                                              | `Promise<string>`         | Creates a new Base32 secret key.                              |
| `generateTOTP`   | `(secret: string, options?: TOTPOptions)`                        | `Promise<string>`         | Generates a time-based OTP.                                   |
| `generateHOTP`   | `(secret: string, options?:HOTPOptions)`                         | `Promise<string>`         | Generates a counter-based OTP.                                |
| `validate`       | `(token: string, secret: string, options?: TOTPValidateOptions)` | `Promise<number \| null>` | Validates a TOTP token and returns the matched delta or null. |

```ts
type HmacAlgorithm = "SHA-1" | "SHA-256" | "SHA-512";

type HOTPOptions = {
  algorithm?: HmacAlgorithm;
  digits?: number; // default: 6
  counter?: number;
};

type TOTPOptions = {
  algorithm?: HmacAlgorithm;
  period?: number; // seconds, default: 30
  digits?: number; // default: 6
  epoch?: number; // ms, default: Date.now()
};

type TOTPValidateOptions = TOTPOptions & {
  window?: number;
};
```

---

## TOTP Validation with Time Window Tolerance

### Time Window Tolerance

The TOTP (Time-Based One-Time Password) validation includes a **time window
tolerance** mechanism to handle clock drift between the client and server. Since
TOTP tokens are time-sensitive, even small differences in system clocks can
cause valid tokens to be rejected.

### How It Works

The `window` parameter defines how many time steps forward and backward the
validator will check when validating a token. For example:

- **Window = 1**: Checks 3 time periods (previous, current, next)

### Delta Values

The validation function returns a **delta** value indicating the time
synchronization status:

| Delta        | Meaning       | Description                                        |
| ------------ | ------------- | -------------------------------------------------- |
| `0`          | Perfect sync  | Token matches current time period                  |
| `-1`         | Client behind | Token matches previous time period                 |
| `1`          | Client ahead  | Token matches next time period                     |
| `null`       | Invalid token | No match found within the allowed window           |

### Security Considerations

- **Default window of 1** provides a good balance between usability and security
- **Larger windows** increase the attack surface and should be used cautiously
- The delta information can be used for monitoring clock drift across clients
- Consider implementing rate limiting to prevent brute force attacks

---

### 🤝 Contributing

Pull requests are welcome\! If you have suggestions for improvements or find any
issues, please feel free to open an issue or create a pull request.

---

### 📚 Resources

- [RFC 6238: TOTP Algorithm](https://datatracker.ietf.org/doc/html/rfc6238)
- [RFC 4226: HOTP Algorithm](https://datatracker.ietf.org/doc/html/rfc4226)

### ✍️ Author

- [Haikel Fazzani](https://github.com/haikelfazzani)

### 📜 License

This project is licensed under the **GNU General Public License v3.0**. See the
[LICENSE](https://www.google.com/search?q=LICENSE) file for details.
