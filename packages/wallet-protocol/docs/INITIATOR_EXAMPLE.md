# Wallet protocol initiator example

This section contains a complete example on how to use all the wallet-protocol packages (@i3m/wallet-protocol, @i3m/wallet-protocol-utils and @i3m/wallet-protocol-api) from the browser point of view.

## Preparing the environment

First we have to start a Node.js project:

```bash
npm init -y
npm i @i3m/wallet-protocol @i3m/wallet-protocol-api @i3m/wallet-protocol-utils
```

## Node.js

For simplicity, we will start with an example using Node.js.

### Creating a transport

The first thing we have to do is to initialize a transport object. These objects define how does the protocol send the messages to the other agent.

In this case we have to use an initiator transport, because we are the initiator agent. We also have to use an HTTP transport as it is the protocol we are using to send the messages.

As previously seen in the general flow of the protocol, the initiator needs the PIN. Transports should be initialized with the `getConnectionString(): Promise<string>` callback function. This function is called when the protocol is executed. As we are using a Node.js application, we will get the PIN reading the `stdin` stream. The code will look like:

```javascript
const { HttpInitiatorTransport } = require('@i3m/wallet-protocol')
const readline = require('readline')

// Creates a readline interface and retrieves a string.
async function getConsolePin() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  })
  return new Promise((executor) => {
    rl.question('Introduce a valid PIN: ', (answer) => {
      rl.close()
      executor(answer)
    })
  })
}

const transport = new HttpInitiatorTransport({ getConnectionString: getConsolePin })
```

### Executing the protocol

After the transport is properly initialized we can execute the protocol. The result is a session object. Sessions contain all the cryptographic information to create a secure channel.

```javascript
const { WalletProtocol, HttpInitiatorTransport } = require('@i3m/wallet-protocol')

async function main() {
  const transport = new HttpInitiatorTransport({ getConnectionString: getConsolePin })
  const protocol = new WalletProtocol(transport)

  // Execute the protocol
  const session = await protocol.run()

  // We can print can store/print the session object using the toJSON function
  const sessionJSON = session.toJSON()
  console.log('Pairing finished', sessionJSON)
}
```

### Recover a session

We can easily recover the session from its JSON as follows:

```javascript
// Recover a session
const recoveredSession = await Session.fromJSON(transport, sessionJSON)
```

### Performing API queries

The easiest way to call the wallet API methods is by using the `@i3m/wallet-protocol-api` package:

```javascript
const { WalletApi } = require('@i3m/wallet-protocol-api')

// ...

async function main() {
  // ...

  // Create API object
  const api = new WalletApi(recoveredSession)
  const identities = await api.identities.list()
  console.log('List of all the identity DIDs', identities)
}
```

### Complete Node.js example

```javascript
const { WalletProtocol, HttpInitiatorTransport, Session } = require('@i3m/wallet-protocol')
const { WalletApi } = require('@i3m/wallet-protocol-api')
const readline = require('readline')

async function getConsolePin() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  })
  return new Promise((executor) => {
    rl.question('Introduce a valid PIN: ', (answer) => {
      rl.close()
      executor(answer)
    })
  })
}

async function main() {
  const transport = new HttpInitiatorTransport({ getConnectionString: getConsolePin })
  const protocol = new WalletProtocol(transport)

  // Execute the protocol
  const session = await protocol.run()

  // We can print can store/print the session object using the toJSON function
  const sessionJSON = session.toJSON()
  console.log('Pairing finished', sessionJSON)

  // Recover a session
  const recoveredSession = await Session.fromJSON(transport, sessionJSON)

  // Create API object
  const api = new WalletApi(recoveredSession)
  const identities = await api.identities.list()
  console.log('List of all the identity DIDs', identities)
}

main().catch((err) => {
  console.log("Unhandleded exception!")
  throw err
})
```

## Browser

Now we are going to explain how to develop it into a browser application.

### Moving it into an HTML file

The HTML file template we are going to use is as follows:

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset='utf-8'>
  <meta http-equiv='X-UA-Compatible' content='IE=edge'>
  <title>Wallet pairing</title>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <script src="./node_modules/@i3m/wallet-protocol/dist/bundles/umd.js"></script>
  <script src="./node_modules/@i3m/wallet-protocol-api/dist/bundles/umd.js"></script>
  <script src="./node_modules/@i3m/wallet-protocol-utils/dist/bundles/umd.js"></script>
</head>
<body onload="main()">
  <button onclick="createSession()">Create session</button>
  <button onclick="deleteSession()">Delete session</button>
  <script src="browser.js"></script>
</body>
</html>
```

Note that we have to import all the libraries in the header and create a browser.js file.

### Adapt the node.js example

To execute the same example that we had in Node.js we have to copy the complete example and change the requires:

```javascript
const { WalletProtocol, HttpInitiatorTransport, Session } = walletProtocol
const { WalletApi } = walletProtocolApi
const { openModal } = walletProtocolUtils

// ...

async function main() {
  // Now we are using the utils package to open a modal to request the PIN
  const transport = new HttpInitiatorTransport({ getConnectionString: openModal })

  // ...  
}
```

Note that now we are using the `@i3m/wallet-protocol-utils` package to open a browser dialog to get ask the user for a PIN.

### Storing the session into the local storage

The `@i3m/wallet-protocol-utils` package contains the `LocalSessionManager` class with stores the session inside the local storage automatically. To use it you have to modify the main function to look as follows:

```javascript
// ...
const { openModal, LocalSessionManager } = walletProtocolUtils

let sessionManager

async function main() {
  // Now we are using the utils package to open a modal to request the PIN
  const transport = new HttpInitiatorTransport({ getConnectionString: openModal })
  const protocol = new WalletProtocol(transport)

  // Initialize the session manager
  sessionManager = new LocalSessionManager(protocol)
  sessionManager
    .$session
    // This function is called each time 
    .subscribe(async (session) => {
      if (session !== undefined) {
        console.log('New session loaded')
      } else {
        console.log('Session deleted')
      }
    })

  // Loads the current session stored into the local storage (if any)
  sessionManager.loadSession()
}
```

Note that we are not executing the protocol with the current flow. To do it we have to add the following function:

```javascript
async function createSession() {
  await sessionManager.createIfNotExists()
}
```

Then, we can add a function to delete the current session:

```javascript
async function deleteSession() {
  await sessionManager.removeSession()
}
```

And lastly, a function to perform a query to the wallet:

```javascript
async function query() {
  const session = sessionManager.session
  if (session !== undefined) {
    const api = new WalletApi(session)
    const identities = await api.identities.list()
    console.log('List of all the identity DIDs', identities)
  } else {
    console.log('Session not created yet')
  }
}
```

### Complete browser example

```javascript
const { WalletProtocol, HttpInitiatorTransport, Session } = walletProtocol
const { WalletApi } = walletProtocolApi
const { openModal, LocalSessionManager } = walletProtocolUtils

let sessionManager

async function main() {
  // Now we are using the utils package to open a modal to request the PIN
  const transport = new HttpInitiatorTransport({ getConnectionString: openModal })
  const protocol = new WalletProtocol(transport)

  sessionManager = new LocalSessionManager(protocol)
  sessionManager
    .$session
    // This function is called each time 
    .subscribe(async (session) => {
      if (session !== undefined) {
        console.log('New session loaded')
      } else {
        console.log('Session deleted')
      }
    })

  await sessionManager.loadSession()
}

async function createSession() {
  await sessionManager.createIfNotExists()
}

async function deleteSession() {
  await sessionManager.removeSession()
}

async function query() {
  const session = sessionManager.session
  if (session !== undefined) {
    const api = new WalletApi(session)
    const identities = await api.identities.list()
    console.log('List of all the identity DIDs', identities)
  } else {
    console.log('Session not created yet')
  }
}
```