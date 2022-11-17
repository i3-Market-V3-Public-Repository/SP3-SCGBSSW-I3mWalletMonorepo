[![License: {{PKG_LICENSE}}](https://img.shields.io/badge/License-{{PKG_LICENSE}}-yellow.svg)](LICENSE)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)
{{GITHUB_ACTIONS_BADGES}}

# {{PKG_NAME}}

{{PKG_DESCRIPTION}}

It provides:

- **PIN dialogs**. A PIN dialog allows to interactively set the PIN in a TypeScript/JavaScript application when a pairing with an i3M-Wallet desktop app is started.
  - `pinDialog` (replaces deprecated `openModal`). It defines the default PIN dialog. In node, it is a promise that resolves to a PIN that is requested through the console to the end user. In browsers, it shows an HTML formulary where to write the PIN, and returns a promise that resolves to that PIN when a user fills it and submits it.
- **Session managers**. A session manager is used to create, remove, set and load wallet-protocol sessions created after successful pairing with a i3M-Wallet app.
  - `SessionManager` (replaces deprecated `LocalSessionManager`). A default session manager that:
    - In browsers it uses the browser's `Local Storage` as a provider for session storage. You can pass as options:
      - `key`: the key where to keep the session data in the LocalStorage.
    - In Node.js it uses a file storage. You can pass as options:
      - `filepath`: a path to the file that will be used to store wallet session data
      - `password`: if provided a key will be derived from the password and the store file will be encrypted.

The wallet protocol description is explained [here](./../../../wallet-protocol/README.md).

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

The appropriate version for browser or node is automatically exported.

You can also download the {{IIFE_BUNDLE}}, the {{ESM_BUNDLE}} or the {{UMD_BUNDLE}} and manually add it to your project, or, if you have already installed `{{PKG_NAME}}` in your project, just get the bundles from `node_modules/{{PKG_NAME}}/dist/bundles/`.

An example of usage could be:

```typescript
YOUR TYPESCRIPT EXAMPLE CODE HERE
```

## API reference documentation

[Check the API](../../docs/API.md)
