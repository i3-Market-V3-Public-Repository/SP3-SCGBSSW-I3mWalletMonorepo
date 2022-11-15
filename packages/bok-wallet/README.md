[![License: EUPL_1.2](https://img.shields.io/badge/license-EUPL_1.2-green.svg)](LICENSE)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)

# @i3m/bok-wallet

An implementation of the base wallet using a bag of keys (keys are independently created at random).. It extends the `BaseWallet` class defined in the [`@i3m/base-wallet`](../base-wallet/) package. The main differences with the [`@i3m/sw-wallet`](../sw-wallet/) is that an `@i3m/bok-wallet` cannot be regenerated with a seed (or mnemonic words), but can import and use arbitrary keys.

## Usage

`@i3m/bok-wallet` can be imported to your project with `npm`:

```console
npm install @i3m/bok-wallet
```

Then either require (Node.js CJS):

```javascript
const bokWallet = require('@i3m/bok-wallet')
```

or import (JavaScript ES module):

```javascript
import * as bokWallet from '@i3m/bok-wallet'
```

## API reference documentation

[Check the API](docs/API.md)
