[![License: EUPL-1.2](https://img.shields.io/badge/license-EUPL--1.2-green.svg)](LICENSE)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)

# @i3m/wallet-protocol-api

A TypeScript/JavaScript library that can be used to easily connect to an i3m Wallet Desktop App. It wraps all the functionalities provided by the wallet's HTTP API into convenient class methods. It works in Node.js (both ESM and CJS) and browsers..

The wallet protocol description is explained [here](../wallet-protocol/README.md)

## Install

In order to use `@i3m/wallet-protocol-api`, you should as well install [`@i3m/wallet-protocol`](https://github.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/tree/public/packages/wallet-protocol). Install both in your NPM project as:

```console
npm install @i3m/wallet-protocol-api @i3m/wallet-protocol
```

The appropriate version for browser or node is automatically exported depending on where it is imported/required (set `browser` to `true` or `false` in your bundler).

You can also download the [IIFE bundle](https://raw.githubusercontent.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/main/dist/bundles/iife.js), the [ESM bundle](https://raw.githubusercontent.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/main/dist/bundles/esm.min.js) or the [UMD bundle](https://raw.githubusercontent.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/main/dist/bundles/umd.js) and manually add it to your project, or, if you have already installed `@i3m/wallet-protocol-api` in your project, just get the bundles from `node_modules/@i3m/wallet-protocol-api/dist/bundles/`.

## Usage

For connecting to the i3M-Wallet application, you need to pair with the wallet in order to obtain a session token:

- Set your wallet in pairing mode. A PIN appears in the screen
- Connect a browser to http://localhost:29170/pairing
  - If session is ON (PIN is not requested), click "Remove session" and then "Start protocol"
  - Fill in the PIN
  - After successful pairing, click "Session to clipboard"

Your clipboard now holds a JSON with a valid token agreed with the token.

Now you can initiate a connection to the wallet as:
  
```typescript
import { HttpInitiatorTransport, Session } from '@i3m/wallet-protocol'
import { WalletApi } from '@i3m/wallet-protocol-api'

const sessionObj = JSON.parse('<PASTE HERE>')

const transport = new HttpInitiatorTransport()
const session = await Session.fromJSON(transport, sessionObj)
const wallet = new WalletApi(session)
```

> It is not recommended to hardcode the token in code, so do NOT use this example in production. Your JSON token should be securely stored/accessed.

## API reference documentation

[Check the API](docs/API.md)
