[![License: EUPL-1.2](https://img.shields.io/badge/license-EUPL--1.2-green.svg)](LICENSE)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)

# {{PKG_NAME}}

{{PKG_DESCRIPTION}}

The wallet protocol description is explained [here](./../../../wallet-protocol/README.md)

## Install

In order to use `{{PKG_NAME}}`, you should as well install [`@i3m/wallet-protocol`](https://github.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/tree/public/packages/wallet-protocol). Install both in your NPM project as:

```console
npm install {{PKG_NAME}} @i3m/wallet-protocol
```

The appropriate version for browser or node is automatically exported depending on where it is imported/required (set `browser` to `true` or `false` in your bundler).

You can also download the {{IIFE_BUNDLE}}, the {{ESM_BUNDLE}} or the {{UMD_BUNDLE}} and manually add it to your project, or, if you have already installed `{{PKG_NAME}}` in your project, just get the bundles from `node_modules/{{PKG_NAME}}/dist/bundles/`.

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

[Check the API](../../docs/API.md)
