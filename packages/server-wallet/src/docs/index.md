[![License: {{PKG_LICENSE}}](https://img.shields.io/badge/license-{{PKG_LICENSE}}-green.svg)](LICENSE)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)

# {{PKG_NAME}}

{{PKG_DESCRIPTION}}

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
> If you are coding TypeScript, types will not be automatically detected when using the specific versions. You can easily get the types in by creating a `{{PKG_NAME}}.d.ts` file with just the line:
>
> ```typescript
> declare module '{{PKG_NAME}}/dist/cjs/index.node' // use the specific file you were importing
> ```

The server wallet uses a file as storage. Optional `filepath` is the path to the Wallet's storage file. If you are using a container it should be a path to a file that persists (like one in a volume)

The wallet's storage-file can be encrypted for added security by passing an optional `password`.

Example of instantiation of a server wallet in typescript:

```typescript
wallet = await serverWalletBuilder({ password: '1735b07cb074bc1057vc130377$(==)(5v0bx23YGSA', filepath: '/path/where/the/wallet/will/store/things' })
```

## Create an identity (DID)

```typescript
const resp = await wallet.identityCreate({
  alias: 'identity1'
})
console.log(`DID for identity1 created: `, resp.did)
```

## List identities

```typescript
const identities = await wallet.identityList({})
console.log('Identities: ', identities)
```

## Generate a signet JWT

You can generate a signature as a JWT for a generic JSON object as, for instance:

```typescript
const objectToSign = {
  field1: 'yellow',
  field2: 'brown'
}
jwt = (await wallet.identitySign({ did: 'one of the dids in the wallet' }, { type: 'JWT', data: { payload: objectToSign } })).signature
```

## Verify a signed JWT

You can also use your wallet to verify a JWT signed by other wallets as:

```typescript
const verification = await wallet.didJwtVerify({ jwt })
if (verification.verification === 'success') {
  // properly verified
} else {
  // failed with error msg in verification.error
}
```

The verification can also check for specific payload claims. An expected value of '' can be used to just check that the claim is in the payload.

```typescript
const verification = await wallet.didJwtVerify({
  jwt,
  expectedPayloadClaims: {
    field1: 'yellow'  // check that "field1"="yellow" is in the JWT payload
    field2: '' // check that "field2" is defined in the JWT payload
  }
})
if (verification.verification === 'success') {
  // properly verified
} else {
  // failed with error msg in verification.error
}
```

## API reference documentation

[Check the API](../../docs/API.md)
