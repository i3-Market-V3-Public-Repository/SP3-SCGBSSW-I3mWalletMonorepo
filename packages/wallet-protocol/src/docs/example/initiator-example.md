# Wallet protocol initiator example

This section contains a complete example on how to pair a JavaScript application running in a browser (hereby the initiator) with the i3M-Wallet app, and then interacting with the wallet from the JS app.

## Installation

We are going to need the following packages:

- [`@i3m/wallet-protocol`](../../): implements the pairing protocol between an initiator (a JS app) and the i3M-Wallet desktop app
- [`@i3m/wallet-protocol-utils`](../../../wallet-protocol-utils/): provides convenient session manager to handle the creation/management of secure sessions using the wallet protocol. A secure session is the result of a successful pairing.
- [`@i3m/wallet-protocol-api`](../../../wallet-protocol-api/): defines convenient methods for all the i3M-Wallet functionalities through the above created secure session that map secure connections

If using NPM, you can just install them from the NPM.js public repository with:

```console
npm i @i3m/wallet-protocol @i3m/wallet-protocol-api @i3m/wallet-protocol-utils
```

Otherwise, you can just download the browser bundles (see each package's documentation)

## Pairing and creating a secure session

The first thing we have to do is to initialize the initiator's transport object. The `transport` object defines how messages are exchanged between the two peers of the protocol, namely the initiator (a JS app) and the wallet.

Put the i3M-Wallet in pairing mode, it will show a PIN. The initiators' `transport` object should be initialized with that PIN. Since the PIN is going to be interactively added by the end user to the JS app, the `transport` requires a `getConnectionString` function that resolves to the user-provided PIN.

The `@i3m/wallet-protocol-utils` package provides a convenient dialog for requesting the PIN to the end-user pairing the JS app and the wallet. In the case of a browser JS app, it opens an HTML formulary to be filled with the PIN. In the case of a Node JS app the PIN is requested in the same terminal the app is running.

As previously seen in the general flow of the protocol, the initiator needs the PIN. Transports should be initialized with the `getConnectionString(): Promise<string>` callback function. This function is called when the protocol is executed. As we are using a Node.js application, we will get the PIN reading the `stdin` stream.

Once we have a `transport` (and so the PIN is shared between the i3M-Wallet and the JS app), we can execute the wallet protocol to create a pairing and establish a secure session. In order to manage protocol execution and the session information, it is convenient to use a `SessionManager`. Once again, the `@i3m/wallet-protocol-utils` package provides a convenient implementation using for the session storage (by default) the LocalStorage in browsers, and a (optionally encrypted) file in node.js.

```typescript
import { WalletProtocol, HttpInitiatorTransport } from '@i3m/wallet-protocol'
import { pinDialog, SessionManager } from '@i3m/wallet-protocol-utils'


const transport = new HttpInitiatorTransport({ getConnectionString: pinDialog })

const protocol = new WalletProtocol(transport)

sessionManager = new SessionManager(protocol)

sessionManager
  .$session
  // We can subscribe to events when the session is deleted/end and when a new one is created
  .subscribe(async (session) => {
    if (session !== undefined) {
      console.log('New session loaded')
    } else {
      console.log('Session deleted')
    }
  })

// Loads the current stored session (if any). Use it to recover a previously created session
sessionManager.loadSession()

// creates a secure session (if it does not exist yet)
sessionManager.createIfNotExists()

```

Obviously the session manager can also be used to remove a session:

```typescript
sessionManager.removeSession()
```

## Interacting with the wallet

Once we have a secure session with the wallet, we can use it to interact with it using its HTTP API, but this could be tedious. The `@i3m/wallet-protocol-api` wraps the wallet HTTP API into convenient methods that can be used to invoke the different functionalities of the wallet. For example, we could easily get a list of identities in the wallet with:

```typescript
...
import { WalletApi } from '@i3m/wallet-protocol-api'
...

// We have already initialized a sessionManager and created a secure sessiot
const api = new WalletApi(sessionManager.session)

// Let us query the identities in the wallet
const identities = await api.identities.list()

console.log('List of all the identity DIDs', identities) 
```
