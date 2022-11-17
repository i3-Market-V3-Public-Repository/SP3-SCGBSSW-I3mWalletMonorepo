[![License: {{PKG_LICENSE}}](https://img.shields.io/badge/License-{{PKG_LICENSE}}-yellow.svg)](LICENSE)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)

# {{PKG_NAME}}

{{PKG_DESCRIPTION}}

The protocol is based on the Bluetooth pairing. To create a secure channel, the user must set the wallet in pairing mode. Then, the wallet will show an 8-digit PIN on the screen. This PIN is composed by the TCP port and the authentication data. When the user introduces the PIN into the browser, it will initiate a direct communication with the wallet performing a mutual authentication and finally creating a secure channel.

![Wallet protocol summary](./protocol-summary.png)

## Installation

`{{PKG_NAME}}` can be imported to your project with `npm`:

```console
npm install {{PKG_NAME}}
```

Then either require (Node.js CJS):

```javascript
const {{PKG_CAMELCASE}} = require('{{PKG_NAME}}')
```

or import (JavaScript ES module):

```javascript
import * as {{PKG_CAMELCASE}} from '{{PKG_NAME}}'
```

The appropriate version for browser or node is automatically exported.

You can also download the {{IIFE_BUNDLE}}, the {{ESM_BUNDLE}} or the {{UMD_BUNDLE}} and manually add it to your project, or, if you have already installed `{{PKG_NAME}}` in your project, just get the bundles from `node_modules/{{PKG_NAME}}/dist/bundles/`.

## Wallet pairing protocol's sequence diagram

The complete wallet protocol sequence diagram is the following:

![Wallet protocol sequence diagram](./wallet-protocol-seq.png)

## Wallet protocol's related libraries

There are 3 libraries related with the wallet protocol.

| **Name**              | **Package**                  | **Description**                            |
|-----------------------|------------------------------|--------------------------------------------|
| Wallet Protocol       | `@i3m/wallet-protocol`       | Main implementation of the wallet protocol, which after successful pairing creates a secure session between the initiator (a JavaScript application) and an i3M-Wallet |
| Wallet Protocol Utils | `@i3m/wallet-protocol-utils` | Utilities to execute the protocol. It includes:<ul><li>A modal to introduce the PIN</li><li>A local storage session manager (for browsers)</li></ul> |
| Wallet Protocol API   | `@i3m/wallet-protocol-api`   | A library that uses a wallet protocol session to call the [`wallet-desktop-openapi`](../../../wallet-desktop-openapi/)  |

### @i3m/wallet-protocol

Create a session with a wallet:

```typescript
import { openModal, LocalSessionManager } from '@i3m/wallet-protocol-utils'
import { HttpInitiatorTransport, WalletProtocol } from '@i3m/wallet-protocol'

// openModal is a function that returns a Promise<string> that resolves to the PIN
async function main(): Promise<string> {
    const transport = new HttpInitiatorTransport({ getConnectionString: openModal })
    const protocol = new WalletProtocol(transport)
    const session = await protocol.run()
}
```

### @i3m/wallet-protocol-utils

Open modal function:

```typescript
import { openModal } from '@i3m/wallet-protocol-utils'

const { openModal, LocalSessionManager } = walletProtocolUtils
```

Create a session with the session manager:

```typescript
import { LocalSessionManager } from '@i3m/wallet-protocol-utils'

const sessionManager = new LocalSessionManager(protocol)

sessionManager
  .$session
  .subscribe((session) => {
    // This callback is executed each time the session changes
    sessionState.innerText = session !== undefined ? 'ON' : 'OFF'
  })

await sessionManager.createIfNotExists()
```

### @i3m/wallet-protocol-api

Create an API object and call it:

```typescript
import { WalletApi } from '@i3m/wallet-protocol-api'

const api = new WalletApi(session)

// Now you can execute any method
api.identities.list()
api.identities.select()
api.identities.create()

// All the methods are described on the @i3m/wallet-desktop-openapi specification.
```

## API reference documentation

[Check the API](../../docs/API.md)

## Initiator example

A complete example on how to program an initiator for the wallet protocol can be found [here](example/initiator-example.md)