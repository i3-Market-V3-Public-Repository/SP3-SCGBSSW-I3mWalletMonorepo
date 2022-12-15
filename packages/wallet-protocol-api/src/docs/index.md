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

> The appropriate version for browser or node should be automatically chosen when importing. However, if your bundler does not import the appropriate module version (node esm, node cjs or browser esm), you can force it to use a specific one by just importing one of the followings:
>
> - `{{PKG_NAME}}/dist/cjs/index.node`: for Node.js CJS module
> - `{{PKG_NAME}}/dist/esm/index.node`: for Node.js ESM module
> - `{{PKG_NAME}}/dist/esm/index.browser`: for browser ESM module
>
> If you are coding TypeScript, types will not be automatically detected when using the specific versions. You can easily get the types in by creating a `{{PKG_NAME}}.d.ts` file with just the line:
>
> ```typescript
> declare module '{{PKG_NAME}}/dist/esm/index.browser' // use the specific file you were importing
> ```

You can also download the {{IIFE_BUNDLE}}, the {{ESM_BUNDLE}} or the {{UMD_BUNDLE}} and manually add it to your project, or, if you have already installed `{{PKG_NAME}}` in your project, just get the bundles from `node_modules/{{PKG_NAME}}/dist/bundles/`.

## Usage

Read the documentation of the [`@i3m/wallet-protocol` package](../../../wallet-protocol/README.md) or go directly to the pairing example in [Wallet pairing and use from a JS application](../../../wallet-protocol/src/docs/example/initiator-example.md).

## API reference documentation

[Check the API](../../docs/API.md)
