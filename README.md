# one-time password (OTP) generator

Node/Browser module for TOPT and HOPT one-time password (OTP) generator based on rfc6238 and rfc4226

## Usage

**generate TOPT**
```js
import { generateTOPT } from "opt-ts";

(async () => {

  const defaultOptions = {
    hash: 'sha-1',
    timeStep: 30,
    digits: 6,
    timestamp: Date.now()
  }

  const code = await generateTOPT("key", defaultOptions?);
  console.log(code);
})();
```

**generate HOPT**
```js
import { generateHOPT } from "opt-ts";

(async () => {
  const counter = 14653
  const hash = 'sha-1'
  const digits = 6

  const code = await generateHOPT("secretKey", counter, hash, digits);
  console.log(code);
})();
```

## Ressouces

- [rfc6238](https://datatracker.ietf.org/doc/html/rfc6238)
- [rfc4226](https://datatracker.ietf.org/doc/html/rfc4226)

# License
GNU GENERAL PUBLIC LICENSE V3