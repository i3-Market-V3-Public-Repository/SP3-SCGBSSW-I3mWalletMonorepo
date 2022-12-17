[![License: EUPL_1.2](https://img.shields.io/badge/license-EUPL_1.2-green.svg)](LICENSE)
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

> The appropriate version (either cjs or esm) should be automatically chosen when importing. However, if your bundler does not import the appropriate module version, you can force it to use a specific one by just importing one of the followings:
>
> - `@i3m/base-wallet/dist/cjs/index.node`: for Node.js CJS module
> - `@i3m/base-wallet/dist/esm/index.node`: for Node.js ESM module
>
> If you are coding TypeScript, types will not be automatically detected when using the specific versions. You can easily get the types in by creating adding to a types declaration file (`.d.ts`) the following line:
>
> ```typescript
> declare module '@i3m/base-wallet/dist/esm/index.browser' // use the specific file you were importing
> ```

## API reference documentation

[Check the API](docs/API.md)
