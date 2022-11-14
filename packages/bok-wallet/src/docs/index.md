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

## API reference documentation

[Check the API](../../docs/API.md)