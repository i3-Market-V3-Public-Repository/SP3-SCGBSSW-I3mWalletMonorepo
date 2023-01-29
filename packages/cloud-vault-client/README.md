[![License: EUPL_1.2](https://img.shields.io/badge/License-EUPL_1.2-yellow.svg)](LICENSE)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)
[![Node.js CI](https://github.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/actions/workflows/build-and-test.yml)
[![Coverage Status](https://coveralls.io/repos/github/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/badge.svg?branch=public)](https://coveralls.io/github/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo?branch=public)

# @i3m/cloud-vault-client

A TypeScript/JavaScript implementation of a client for the i3M-Wallet Cloud-Vault server

## Install and use

`@i3m/cloud-vault-client` can be imported to your project with `npm`:

```console
npm install @i3m/cloud-vault-client
```

Then either require (Node.js CJS):

```javascript
const cloudVaultClient = require('@i3m/cloud-vault-client')
```

or import (JavaScript ES module):

```javascript
import * as cloudVaultClient from '@i3m/cloud-vault-client'
```

> The appropriate version for node should be automatically chosen when requiring/importing. However, if your bundler does not import the appropriate module version (node esm, node cjs), you can force it to use a specific one by just importing one of the followings:
>
> - `@i3m/cloud-vault-client/dist/cjs/index.node`: for Node.js CJS module
> - `@i3m/cloud-vault-client/dist/esm/index.node`: for Node.js ESM module
>
> If you are coding TypeScript, types will not be automatically detected when using the specific versions. You can easily get the types in by creating adding to a types declaration file (`.d.ts`) the following line:
>
> ```typescript
> declare module '@i3m/cloud-vault-client/dist/esm/index.node' // use the specific file you were importing
> ```

## Usage example

```typescript
YOUR TYPESCRIPT EXAMPLE CODE HERE
```

## API reference documentation

[Check the API](docs/API.md)
