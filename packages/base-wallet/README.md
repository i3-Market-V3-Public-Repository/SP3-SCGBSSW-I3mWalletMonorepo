[![License: EUPL-1.2](https://img.shields.io/badge/license-EUPL--1.2-green.svg)](LICENSE)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)

# @i3m/base-wallet

A base packet with a reference TypeScript implementation (called BaseWallet) of the required functionalities for the i3-market wallet. It makes use of a KeyWallet interface that allows delegating the complexity of the wallet key management to other packages, like the sw-wallet, bok-wallet, and hw-wallet

## Usage

`@i3m/base-wallet` can be imported to your project with `npm`:

```console
npm install @i3m/base-wallet
```

Then either require (Node.js CJS):

```javascript
const baseWallet = require('@i3m/base-wallet')
```

or import (JavaScript ES module):

```javascript
import * as baseWallet from '@i3m/base-wallet'
```

## API reference documentation

[Check the API](./docs/API.md)
