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

The appropriate version for browser or node is automatically exported depending on where it is imported/required (set `browser` to `true` or `false` in your bundler).

You can also download the [IIFE bundle](https://raw.githubusercontent.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/main/dist/bundles/iife.js), the [ESM bundle](https://raw.githubusercontent.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/main/dist/bundles/esm.min.js) or the [UMD bundle](https://raw.githubusercontent.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/main/dist/bundles/umd.js) and manually add it to your project, or, if you have already installed `@i3m/wallet-protocol-api` in your project, just get the bundles from `node_modules/@i3m/wallet-protocol-api/dist/bundles/`.

## Usage

Read the documentation of the [`@i3m/wallet-protocol` package](../../../wallet-protocol/README.md) or go directly to the pairing example in [Wallet pairing and use from a JS application](../wallet-protocol/src/docs/example/initiator-example.md).

## API reference documentation

[Check the API](docs/API.md)
