[![License: EUPL_1.2](https://img.shields.io/badge/license-EUPL_1.2-green.svg)](LICENSE)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)

# @i3m/wallet-protocol-api

A TypeScript/JavaScript library that can be used to easily connect to an i3m Wallet Desktop App. It wraps all the functionalities provided by the wallet's HTTP API into convenient class methods. It works in Node.js (both ESM and CJS) and browsers.

The wallet protocol description is explained [here](../wallet-protocol/README.md)

## Install

In order to use `@i3m/wallet-protocol-api`, you should as well install [`@i3m/wallet-protocol`](https://github.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/tree/public/packages/wallet-protocol). Install both in your NPM project as:

```console
npm install @i3m/wallet-protocol-api @i3m/wallet-protocol
```

> The appropriate version for browser or node should be automatically chosen when importing. However, if your bundler does not import the appropriate module version (node esm, node cjs or browser esm), you can force it to use a specific one by just importing one of the followings:
>
> - `@i3m/wallet-protocol-api/dist/cjs/index.node`: for Node.js CJS module
> - `@i3m/wallet-protocol-api/dist/esm/index.node`: for Node.js ESM module
> - `@i3m/wallet-protocol-api/dist/esm/index.browser`: for browser ESM module
>
> If you are coding TypeScript, types will not be automatically detected when using the specific versions. You can easily get the types in by creating a `@i3m/wallet-protocol-api.d.ts` file with just the line:
>
> ```typescript
> declare module '@i3m/wallet-protocol-api/dist/esm/index.browser' // use the specific file you were importing
> ```

You can also download the [IIFE bundle](https://raw.githubusercontent.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/main/dist/bundles/iife.js), the [ESM bundle](https://raw.githubusercontent.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/main/dist/bundles/esm.min.js) or the [UMD bundle](https://raw.githubusercontent.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/main/dist/bundles/umd.js) and manually add it to your project, or, if you have already installed `@i3m/wallet-protocol-api` in your project, just get the bundles from `node_modules/@i3m/wallet-protocol-api/dist/bundles/`.

## Usage

Read the documentation of the [`@i3m/wallet-protocol` package](../../../wallet-protocol/README.md) or go directly to the pairing example in [Wallet pairing and use from a JS application](../wallet-protocol/src/docs/example/initiator-example.md).

## API reference documentation

[Check the API](docs/API.md)
