[![License: {{PKG_LICENSE}}](https://img.shields.io/badge/license-{{PKG_LICENSE}}-green.svg)](LICENSE)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)

# {{PKG_NAME}}

{{PKG_DESCRIPTION}}. It extends the `BaseWallet` class defined in the [`@i3m/base-wallet`](../base-wallet/) package. The main differences with the [`@i3m/sw-wallet`](../sw-wallet/) is that an `@i3m/bok-wallet` cannot be regenerated with a seed (or mnemonic words), but can import and use arbitrary keys.

## Usage

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

> The appropriate version (either cjs or esm) should be automatically chosen when importing. However, if your bundler does not import the appropriate module version, you can force it to use a specific one by just importing one of the followings:
>
> - `{{PKG_NAME}}/dist/cjs/index.node`: for Node.js CJS module
> - `{{PKG_NAME}}/dist/esm/index.node`: for Node.js ESM module
>
> If you are coding TypeScript, types will not be automatically detected when using the specific versions. You can easily get the types in by creating adding to a types declaration file (`.d.ts`) the following line:
>
> ```typescript
> declare module '{{PKG_NAME}}/dist/esm/index.browser' // use the specific file you were importing
> ```

## API reference documentation

[Check the API](../../docs/API.md)
