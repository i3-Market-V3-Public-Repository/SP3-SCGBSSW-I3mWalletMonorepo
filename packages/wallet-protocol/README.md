[![License: EUPL_1.2](https://img.shields.io/badge/License-EUPL_1.2-yellow.svg)](LICENSE)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)

# @i3m/wallet-protocol

The implementation of a protocol that can securely connect the i3M Wallet with a JS application.

Heavily inspired in the Bluetooth pairing, the user must set the wallet in pairing mode before executing the protocol. Then, the wallet will show an 8-digit PIN on the screen. The user should next introduce the PIN into the JS application. The PIN includes authentication data and the parameters required to connect to the wallet. The JS application initiates the wallet protocol that will result in a secure channel between that app and the wallet.

![Wallet protocol summary](src/docs/protocol-summary.png)

There are 3 libraries related with the wallet protocol.

| **Name**              | **Package**                                                               | **Description** |
|-----------------------|---------------------------------------------------------------------------|-----------------|
| Wallet Protocol       | [`@i3m/wallet-protocol`](../../README.md)                                 | Main implementation of the wallet protocol, which after successful pairing creates a secure session between the initiator (a JavaScript application) and an i3M-Wallet |
| Wallet Protocol Utils | [`@i3m/wallet-protocol-utils`](../../../wallet-protocol-utils/README.md)  | Utilities to execute the protocol both in browser and node JS. It includes:<ul><li>Dialogs to introduce the PIN</li><li>Session managers</li></ul> |
| Wallet Protocol API   | [`@i3m/wallet-protocol-api`](../../../wallet-protocol-api/README.md)      | A library that uses a wallet protocol session to call the [`wallet-desktop-openapi`](../../../wallet-desktop-openapi/) |

## Installation

`@i3m/wallet-protocol` can be imported to your project with `npm`:

```console
npm install @i3m/wallet-protocol
```

Then either require (Node.js CJS):

```javascript
const walletProtocol = require('@i3m/wallet-protocol')
```

or import (JavaScript ES module):

```javascript
import * as walletProtocol from '@i3m/wallet-protocol'
```

The appropriate version for browser or node is automatically exported.

You can also download the [IIFE bundle](https://raw.githubusercontent.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/main/dist/bundles/iife.js), the [ESM bundle](https://raw.githubusercontent.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/main/dist/bundles/esm.min.js) or the [UMD bundle](https://raw.githubusercontent.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/main/dist/bundles/umd.js) and manually add it to your project, or, if you have already installed `@i3m/wallet-protocol` in your project, just get the bundles from `node_modules/@i3m/wallet-protocol/dist/bundles/`.

## API reference documentation

[Check the API](docs/API.md)

## Example of wallet pairing and use from a JS application

A complete example a complete example on how to pair a JavaScript application running in a browser with the i3M-Wallet app, and then interacting with the wallet from the JS app can be found [here](src/docs/example/initiator-example.md).

## Wallet pairing protocol's sequence diagram

The complete wallet protocol sequence diagram is the following:

![Wallet protocol sequence diagram](src/docs/wallet-protocol-seq.png)