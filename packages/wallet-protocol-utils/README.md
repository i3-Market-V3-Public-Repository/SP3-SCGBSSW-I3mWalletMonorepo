[![License: EUPL_1.2](https://img.shields.io/badge/License-EUPL_1.2-yellow.svg)](LICENSE)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)
[![Node.js CI](https://github.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/actions/workflows/automatic-release.yml/badge.svg)](https://github.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/actions/workflows/automatic-release.yml)

# @i3m/wallet-protocol-utils

A set of utilities for the wallet protocol. It includes dialogs for setting the PIN in browser JS apps and Node.js, and session managers for managing wallet-protocol's session obtained after successful pairing with an i3M-Wallet desktop app.

It provides:

- **PIN dialogs**. A PIN dialog allows to interactively set the PIN in a TypeScript/JavaScript application when a pairing with an i3M-Wallet desktop app is started.
  - `pinDialog` (replaces deprecated `openModal`). It defines the default PIN dialog. In node, it is a promise that resolves to a PIN that is requested through the console to the end user. In browsers, it shows an HTML formulary where to write the PIN, and returns a promise that resolves to that PIN when a user fills it and submits it.
- **Session managers**. A session manager is used to create, remove, set and load wallet-protocol sessions created after successful pairing with a i3M-Wallet app.
  - `SessionManager` (replaces deprecated `LocalSessionManager`). A default session manager that:
    - In browsers it uses the browser's `Local Storage` as a provider for session storage. You can pass as options:
      - `key`: the key where to keep the session data in the LocalStorage.
    - In Node.js it uses a file storage. You can pass as options:
      - `filepath`: a path to the file that will be used to store wallet session data
      - `password`: if provided a key will be derived from the password and the store file will be encrypted.

The wallet protocol description is explained [here](../wallet-protocol/README.md).

## Usage

`@i3m/wallet-protocol-utils` can be imported to your project with `npm`:

```console
npm install @i3m/wallet-protocol-utils
```

Then either require (Node.js CJS):

```javascript
const walletProtocolUtils = require('@i3m/wallet-protocol-utils')
```

or import (JavaScript ES module):

```javascript
import * as walletProtocolUtils from '@i3m/wallet-protocol-utils'
```

The appropriate version for browser or node is automatically exported.

You can also download the [IIFE bundle](https://raw.githubusercontent.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/public/packages/wallet-protocol-utils/dist/bundles/iife.js), the [ESM bundle](https://raw.githubusercontent.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/public/packages/wallet-protocol-utils/dist/bundles/esm.min.js) or the [UMD bundle](https://raw.githubusercontent.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/public/packages/wallet-protocol-utils/dist/bundles/umd.js) and manually add it to your project, or, if you have already installed `@i3m/wallet-protocol-utils` in your project, just get the bundles from `node_modules/@i3m/wallet-protocol-utils/dist/bundles/`.

## API reference documentation

[Check the API](docs/API.md)
