[![License: EUPL-1.2](https://img.shields.io/badge/license-EUPL--1.2-green.svg)](LICENSE)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)


# @i3-market/non-repudiation-protocol

Library for the i3-market non-repudiation protocol that helps generate/verifying the necessary proofs and the received block of data.

## API reference documentation

[Check the API](./docs/API.md)

## Usage

`@i3-market/non-repudiation-protocol` can be imported to your project with `npm`:

```console
npm install @i3-market/non-repudiation-protocol
```

Then either require (Node.js CJS):

```javascript
const nonRepudiationProtocol = require('@i3-market/non-repudiation-protocol')
```

or import (JavaScript ES module):

```javascript
import * as nonRepudiationProtocol from '@i3-market/non-repudiation-protocol'
```

The appropriate version for browser or node is automatically exported.

You can also download the [IIFE bundle](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/raw/master/dist/dist/bundles/iife.js?inline=false), the [ESM bundle](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/raw/master/dist/dist/bundles/esm.min.js?inline=false) or the [UMD bundle](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/raw/master/dist/dist/bundles/umd.js?inline=false) and manually add it to your project, or, if you have already installed `@i3-market/non-repudiation-protocol` in your project, just get the bundles from `node_modules/@i3-market/non-repudiation-protocol/dist/bundles/`.

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
  const npProvider = new NonRepudiationOrig(dataExchangeId, providerJwks, consumerJwks.publicJwk, block)

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
)
nrp()
```

### Example for an i3-MARKET Consumer

```typescript
async nrp() => {
  /**
   * Intialize the non-repudiation protocol as the destination of the data block.
   * You need:
   *  - the id of this data exchange
   *  - a pair of public private JWK (the consumer's one for this data exchange)
   *  - the provider's public key in JWK
   */
  const npConsumer = new NonRepudiationDest(dataExchangeId, consumerJwks, providerJwks.publicJwk)

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

  // Verify PoP. If verification passes the pop is added to npConsumer.block.pop; otherwise it throws an error.
  await npConsumer.verifyPoP(pop, secret)

  // Decrypt cipherblock (it is already stored in npConsumer.block.jwe) and verify that the hash(decrypted block) is equal to the committed one (in the original PoO). If verification fails, it throws an error.
  const decryptedBlock = await npConsumer.decrypt()
)
nrp()
```
