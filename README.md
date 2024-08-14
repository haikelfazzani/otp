# one-time password (OTP) generator

🔐 Deno/Bun/Node/Browser module for TOTP and HOTP generator based on
RFC 6238 and RFC 4226 🗝️

- Zero dependencies: Works seamlessly across different environments without requiring additional libraries.
- Supports TOTP and HOTP: Generate both time-based and counter-based one-time passwords

<div align="center" style="width:100%; text-align:center; margin-bottom:20px;">
  <img src="https://badgen.net/bundlephobia/minzip/one-time-pass" alt="one-time-pass" />
  <img src="https://badgen.net/bundlephobia/dependency-count/one-time-pass" alt="one-time-pass" />
  <img src="https://badgen.net/npm/v/one-time-pass" alt="one-time-pass" />
  <img src="https://badgen.net/npm/dt/one-time-pass" alt="one-time-pass" />
  <img src="https://data.jsdelivr.com/v1/package/npm/one-time-pass/badge" alt="one-time-pass"/>
</div>

Try it out on JSFiddle: [Live Demo](https://jsfiddle.net/HaikelFazzani/e5dz6g2x/2/)

# Install

```
npm i one-time-pass
```

# Usage

## Import

```js
import { generateTOTP } from "one-time-pass";
// Deno 
import { generateTOTP } from "npm:one-time-pass";
// Nodejs
const { generateTOTP } = require("one-time-pass");

// Or include it via CDN
<script src="https://cdn.jsdelivr.net/npm/one-time-pass/dist/index.umd.js"></script>

window.otp.generateTOTP("key");
```

## Examples

**generate TOTP**

```js
import { generateTOTP } from "one-time-pass";

(async () => {

  const defaultOptions = {
    hash: 'SHA-1',
    timeStep: 30, // epoch interval
    digits: 6,
    timestamp: Date.now()
  }

  const code = await generateTOTP("key", defaultOptions?);
  console.log(code);
})();
```

**generate HOTP**

```js
import { generateHOTP } from "one-time-pass";

(async () => {
  const counter = 14653;
  const hash = "SHA-1";
  const digits = 6;

  const code = await generateHOTP("secretKey", counter, hash, digits);
  console.log(code);
})();
```

## Ressouces

- [rfc6238](https://datatracker.ietf.org/doc/html/rfc6238)
- [rfc4226](https://datatracker.ietf.org/doc/html/rfc4226)

### Notes

- We welcome pull requests! Feel free to contribute to this project.

### Author

- [Haikel Fazzani](https://github.com/haikelfazzani)

# License

GNU GENERAL PUBLIC LICENSE V3
