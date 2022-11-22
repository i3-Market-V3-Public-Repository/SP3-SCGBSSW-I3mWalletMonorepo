[![License: {{PKG_LICENSE}}](https://img.shields.io/badge/license-{{PKG_LICENSE}}-green.svg)](LICENSE)
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

Read the documentation of the [`@i3m/wallet-protocol` package](../../../wallet-protocol/README.md) or go directly to the pairing example in [Wallet pairing and use from a JS application](../../../wallet-protocol/src/docs/example/initiator-example.md).

## API reference documentation

[Check the API](../../docs/API.md)
