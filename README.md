# TOTP hash based on RFC 6238

TOTP is a 2FA method that leverages a time-based mechanism to generate one-time
passwords.

## Usage

**generate TOPT**
```js
import { generateTOPT } from "opt-ts";

(async () => {

  const options = {
    hash: 'sha-1',
    timeStep: 30,
    digits: 6,
    timestamp: Date.now()
  }

  const code = await generateTOPT("key", options?);
  console.log(code);
})();
```

**generate HOPT**
```js
import { generateHOPT } from "opt-ts";

(async () => {
  const hash = 'sha-1'
  const digits = 6
  const counter = 14653

  const code = await generateHOPT("secretKey", counter, hash, digits);
  console.log(code);
})();
```

## Ressouces

- [rfc6238](https://datatracker.ietf.org/doc/html/rfc6238)
- [rfc4226](https://datatracker.ietf.org/doc/html/rfc4226)

# License
GNU GENERAL PUBLIC LICENSE V3