# i3m-wallet-monorepo

A monorepo containing all the packages related to the i3-MARKET Wallet, a.k.a. i3M Wallet.

## Documentation

Please go directly to the READMEs of the different packages ;-)

Several packages are provided in this repo, but you are likely only needing:

- [**i3M Server Wallet**](./packages/server-wallet/). It is an interactionless wallet implementation not requiring any user interaction. It has been designed to be operated by a 'machine' or service. Current implementation is in TypeScript/JavaScript and ca be easily imported to your project with NPM/Yarn.
- [**i3M-Wallet Desktop App**](https://github.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/releases/latest). It is a desktop application (Windows, MacOS, and Linux) thought to be operated by end users. The app ca be securely paired to any application, allowing the application to interact with the wallet through an HTTP API. Wallet actions requested by any application will require explicit confirmation of the end-user through the app interface (window).
- [**i3M Wallet Protocol API**](./packages/wallet-protocol-api/). A TypeScript/JavaScript library that can be used to easily connect to an i3M Wallet Desktop App. It wraps all the functionalities provided by the wallet's HTTP API into convenient class methods. It works in Node.js (both ESM and CJS) and browsers. Follow [the pairing example](packages/wallet-protocol/src/docs/example/initiator-example.md) to properly pair your JS application to the wallet and start using the Wallet API.

In order to get a better understanding of what functionalities of the Wallet are provided to paired applications, just open the [i3M-Wallet OpenAPI Specification](./packages/wallet-desktop-openapi/openapi.json) or visualize it online at [editor.swagger.io](https://editor.swagger.io/?url=https://raw.githubusercontent.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/public/packages/wallet-desktop-openapi/openapi.yaml).

## i3M-Wallet DEVELOPERS ONLY

```bash
# Install root dependencies (lerna)
npm i

# for development of all packages
npm run install:dev

# for development of libraries
npm run install:libs

# for development of wallet:desktop
npm run install:desktop
# Starts the i3M wallet desktop application
npm start
# Starts the i3M wallet desktop application in watch mode.
# The running app will be auto updated while changing the code.
npm start:watch
```
