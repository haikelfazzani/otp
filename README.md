# one-time password (OTP) generator

Zero dependencies 🔐 Node/Browser module for TOTP and HOTP generator based on RFC 6238 and RFC 4226 🗝️

<div align="center" style="width:100%; text-align:center; margin-bottom:20px;">
  <img src="https://badgen.net/bundlephobia/minzip/one-time-pass" alt="one-time-pass" />
  <img src="https://badgen.net/bundlephobia/dependency-count/one-time-pass" alt="one-time-pass" />
  <img src="https://badgen.net/npm/v/one-time-pass" alt="one-time-pass" />
  <img src="https://badgen.net/npm/dt/one-time-pass" alt="one-time-pass" />
  <img src="https://data.jsdelivr.com/v1/package/npm/one-time-pass/badge" alt="one-time-pass"/>
</div> 

## Usage

**generate TOTP**
```js
import { generateTOTP } from "one-time-pass";

(async () => {

  const defaultOptions = {
    hash: 'sha-1',
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
  const counter = 14653
  const hash = 'sha-1'
  const digits = 6

  const code = await generateHOTP("secretKey", counter, hash, digits);
  console.log(code);
})();
```

Or include it via jsDelivr CDN (UMD):
```html
<script src="https://cdn.jsdelivr.net/npm/one-time-pass/dist/index.umd.js"></script>
<!-- Access via global object : window.OTP -->

window.OTP.generateTOTP("key");
```


## Ressouces

- [rfc6238](https://datatracker.ietf.org/doc/html/rfc6238)
- [rfc4226](https://datatracker.ietf.org/doc/html/rfc4226)

### Notes
- All pull requests are welcome, feel free.

### Author
- [Haikel Fazzani](https://github.com/haikelfazzani)

# License
GNU GENERAL PUBLIC LICENSE V3