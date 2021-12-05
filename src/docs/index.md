[![License: EUPL-1.2](https://img.shields.io/badge/license-EUPL--1.2-green.svg)](LICENSE)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)
{{GITHUB_ACTIONS_BADGES}}

# {{PKG_NAME}}

Library for the i3-market non-repudiation protocol that helps generate/verifying the necessary proofs and the received block of data.

## API reference documentation

[Check the API](./docs/API.md)

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

### Example for an i3-MARKET Provider

```typescript
async nrp() => {
  /**
   * Intialize the non-repudiation protocol as the origin. Internally, a one-time secret is created and the block is encrypted.
   * You need:
   *  - the id of this data exchange
   *  - a pair of public private JWK (the provider's one for this data exchange)
   *  - the consumer's public key in JWK
   *  - the block of data to send as a Uint8Array
   */
  const npProvider = new {{PKG_CAMELCASE}}.NonRepudiationOrig(dataExchangeId, providerJwks, consumerJwks.publicJwk, block)

  // Create the proof of origin (PoO)
  const poo = await npProvider.generatePoO()
  
  // Send the cipherblock in npProvider.block.jwe along with the poo to the consumer
  ...

  // Receive proof of reception (PoR) and stored in variable por
  ...

  // Verify PoR. If verification passes the por is added to npProvider.block.por; otherwise it throws an error.
  await npProvider.verifyPoR(por)

  // Create proof of publication. It connects to the ledger and publishes the secret that can be used to decrypt the cipherblock
  const pop = await npProvider.generatePoP()

  // Send pop to the consumer. The PoP includes the secret to decrypt the cipherblock; although the consumer could also get the secret from the smart contract
  ...
)
nrp()
```

### Example for an i3-MARKET Consumer

```typescript
async nrp() => {
  /** you need a pair of public-private keys as JWK in one of the EC supported 
   * curves (P-256, P-384, P-521).
   * If you already have a random private key in hex, base64 or Uint8Array, you
   * can easily create the key pair with the generateKeys utility function.
   * An example with a key in hex format would be
   */
  const privKey = '0x4b7903c8fe1824ba5329939c7d2c4318307794a544f2eb5fb3b6536210c98677'
  const consumerJwks = await {{PKG_CAMELCASE}}.generateKeys(SIGNING_ALG, providerPrivKeyHex)
  
  /**
   * Intialize the non-repudiation protocol as the destination of the data block.
   * You need:
   *  - the id of this data exchange. A base64url-no-padding encoding of a uint256
   *  - a pair of public private JWK (the consumer's one for this data exchange)
   *  - the provider's public key in JWK
   */
  const npConsumer = new NonRepudiationDest(dataExchangeId, consumerJwks, providerPublicJwk)

  // Receive poo and cipherblock (in JWE string format)
  ...

  // Verify PoO. If verification passes the poo is added to npConsumer.block.poo and cipherblock to npConsumer.block.cipherblock; otherwise it throws an error.
  await npConsumer.verifyPoO(poo, cipherblock)
  
  // Create the proof of reception (PoR). It is also added to npConsumer.block.por
  const por = await npConsumer.generatePoR()

  // Send PoR to Provider
  ...

  // Receive (or retrieve from ledger) secret in JWJ and proof of publication (PoR) and stored them in secret and pop.
  ...

  // Verify PoP. If verification passes the pop is added to npConsumer.block.pop, and the secret to npConsumer.block.secret; otherwise it throws an error.
  await npConsumer.verifyPoP(pop)

  // Just in case the PoP is not received, the secret can be downloaded from the ledger. The function downloads the secret and stores it to npConsumer.block.secret
  await npConsumer.getSecretFromLedger()

  // Decrypt cipherblock and verify that the hash(decrypted block) is equal to the committed one (in the original PoO). It is assumed must have been obtained first, either inside the PoP or from the ledger. If verification fails, it throws an error.
  const decryptedBlock = await npConsumer.decrypt()
)
nrp()
```
