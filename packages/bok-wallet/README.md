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

> The appropriate version for browser or node should be automatically chosen when importing. However, if your bundler does not import the appropriate module version (node esm, node cjs or browser esm), you can force it to use a specific one by just importing one of the followings:
>
> - `@i3m/bok-wallet/dist/cjs/index.node`: for Node.js CJS module
> - `@i3m/bok-wallet/dist/esm/index.node`: for Node.js ESM module
> - `@i3m/bok-wallet/dist/esm/index.browser`: for browser ESM module
>
> If you are coding TypeScript, types will not be automatically detected when using the specific versions. You can easily get the types in by creating a `@i3m/bok-wallet.d.ts` file with just the line:
>
> ```typescript
> declare module '@i3m/bok-wallet/dist/esm/index.browser' // use the specific file you were importing
> ```

## API reference documentation

[Check the API](docs/API.md)
