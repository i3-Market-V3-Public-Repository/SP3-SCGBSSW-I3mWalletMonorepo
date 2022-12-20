[![License: EUPL-1.2](https://img.shields.io/badge/license-EUPL--1.2-green.svg)](LICENSE)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)
{{GITHUB_ACTIONS_BADGES}}

# {{PKG_NAME}}

Library for handling non-repudiation proofs in the i3-MARKET ecosystem. It is a core element of the Conflict Resolution system in i3-MARKET ([Read more here](https://github.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-CR-Documentation#conflict-resolution--non-repudiation-protocol)).

The library enables implementation of:

1. The **non-repudiation protocol** of a data exchange
2. **The Conflict-Resolver Service**, which can be queried to check completeness of the non-repudiation protocol and/or solve a dispute.

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

### Example for an i3-MARKET Provider running the Non-Repudiation Protocol

> The NRP provider is likely a service (machine) and therefore will likely run a server wallet, which has all the functionalities of the i3M Wallet but requires no user interaction. Data sharing agreements, however, should be signed by a person, hereby the provider operator, which is also responsible for creating the public-private key pair for the provider service.

Before starting the agreement you need:

- **A private key for signing the non-repudiation proofs** in one of the EC supported curves (P-256, P-384, P-521). Key format must be JSON Web Key (JWK).
  
  >The provider operator can easily create the key pair with the `generateKeys` utility function. For example:
  >
  >```typescript
  >const providerJwks = await {{PKG_CAMELCASE}}.generateKeys('ES256')
  >```
  >
  > The key pair can be stored in the provider operator's wallet as:
  >
  >```typescript
  >const keyPair = {
  >  privateJwk: await parseJwk(providerJwks.privateJwk, true),
  >  publicJwk: await parseJwk(providerJwks.publicJwk, true)
  >}
  >
  >const response = await providerOperatorWallet.resources.create({ resource: keyPair, type: 'KeyPair' })
  >```
  >
  > For an example of connecting to an I3M-Wallet desktop app, please refer to the consumer example

- **Import a DLT account to the (service) provider wallet with funds to execute the NRP** In this example we assume that the provider runs a `@i3m/server-wallet`.
  
  >You can easily create a provider server wallet and import a private key with funds.
  >
  >Assuming you have the server-wallet encrypted storage in path `STORAGE_PATH` encrypted with password `STORAGE_PASSWORD`, and a DLT private key of an account with enough funds in `DLT_PRIVATE_KEY`:
  >
  >```typescript
  >serverWalletBuilder = (await import('@i3m/server-wallet')).serverWalletBuilder
  >
  >// Setup provider wallet
  >providerWallet = await serverWalletBuilder({ password: STORAGE_PASSWORD, reset: true, filepath: STORAGE_PATH })
  >
  >// Import DLT account
  >await providerWallet.importDid({
  >  alias: 'provider',
  >  privateKey: DLT_PRIVATE_KEY
  >})
  >const availableIdentities = await providerWallet.identityList({ alias: 'provider' })
  >
  >// The provider DID
  >const providerDid = availableIdentities[0]
  >
  >// The provider address on the DLT
  >const providerDltAddress = {{PKG_CAMELCASE}}.getDltAddress(DLT_PRIVATE_KEY)

- The provider operator has already agreed and signed with the consumer a [`DataSharingAgreement`](https://github.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/blob/public/packages/wallet-desktop-openapi/types/openapi.d.ts) that is stored in object variable `dataSharingAgreement` and that contains a given `DataExchangeAgreement` in `dataSharingAgreement.dataExchangeAgreement` such as:
  
  ```typescript
  {
    // Public key of the origin (data provider) for verifying the proofs she/he issues. The format is a JSON-stringified alphabetically-sorted JWK.
    // You can easily create it as:
    // await {{PKG_CAMELCASE}}.parseJwk(providerJwks.publicJwk, true)
    orig: '{"alg":"ES256","crv":"P-256","kty":"EC","x":"GjUjtzZWRjA9QSpXPDiN8-OO2Ui93mxbxhbLiP0lw4k","y":"YUtjUCIHbqq71Y467ub4Silqqms39RqR_bMPhiso4ws"}',
    
    // Public key of the destination (data consumer). The format is a JSON-stringified alphabetically-sorted JWK.
    dest: '{"alg":"ES256","crv":"P-256","kty":"EC","x":"VXsBuOZwVjhofJV4kAhba6wn1EYDwUIkgXb2fVnL8xc","y":"h4fL5Qv4EYt7XdKqdIy1ZJs4_QWYDkY1zUzSoI61N7Y"}',

    // Encryption algorithm used to encrypt blocks. Either AES-128-GCM ('A128GCM') or AES-256-GCM ('A256GCM)
    encAlg: 'A256GCM',

    // Signing algorithm used to sign the proofs. It'e ECDSA secp256r1 with key lengths: either 'ES256', 'ES384', or 'ES512' 
    signingAlg: 'ES256',
    
    // Hash algorith used to compute digest/commitments. It's SHA2 with different output lengths: either 'SHA-256', 'SHA-384' or 'SHA-512'
    hashAlg: 'SHA-256',
    
    // The ledger smart contract EIP-55 address on the DLT
    ledgerContractAddress: '0x8d407A1722633bDD1dcf221474be7a44C05d7c2F',
    
    // The orig (data provider) EIP-55 address in the DLT (hexadecimal).
    // It should match providerDltAddress
    ledgerSignerAddress: '0x17bd12C2134AfC1f6E9302a532eFE30C19B9E903',
    
    // Maximum acceptable delay between the issuance of the proof of origing (PoO) by the orig and the reception of the proof of reception (PoR) by the orig
    pooToPorDelay: 10000,
    
    // Maximum acceptable delay between the issuance of the proof of origing (PoP) by the orig and the reception of the proof of publication (PoR) by the dest
    pooToPopDelay: 30000,
    
    // If the dest (data consumer) does not receive the PoP, it could still get the decryption secret from the DLT. This defines the maximum acceptable delay between the issuance of the proof of origing (PoP) by the orig and the publication (block time) of the secret on the blockchain.
    pooToSecretDelay: 180000
  }
  ```

  The provider operator has stored the `dataSharingAgreement` in the provider wallet with:

  ```typescript
  await providerWallet.resourceCreate({
    type: 'Contract',
    resource: {
      dataSharingAgreement,
      keyPair: {
        publicJwk: await {{PKG_CAMELCASE}}.parseJwk(providerJwks.publicJwk, true),
        privateJwk: await {{PKG_CAMELCASE}}.parseJwk(providerJwks.privateJwk, true)
      }
    }
  })
  ```

  The wallet will verify the agreement schema, the signatures (made by the consumer and the provider operator), the provided `keyPair`, and that the `keyPair.publcJwk` matches `dataSharingAgreement.dataExchangeAgreement.orig`.

And now you are ready to start a `dataExchange` for a given block of data `block` of a given `DataExchangeAgreement`.

```typescript
async nrp() => {

  const dataExchangeAgreement: {{PKG_CAMELCASE}}.DataExchangeAgreement = dataSharingAgreement.dataExchangeAgreement

  // Now let us create a NRP DLT Agent for the provider. 
  providerDltAgent = new {{PKG_CAMELCASE}}.I3mServerWalletAgentOrig(providerWallet, providerDid)
  
  // dataExchangeAgreement.ledgerSignerAddress should match (await providerWallet.getAddress())
  if (dataExchangeAgreement.ledgerSignerAddress !== await providerWallet.getAddress()) {
    throw new Error('not maching')
  }

  /**
   * Intialize the non-repudiation protocol as the origin. Internally, a one-time secret is created and the block is encrypted. They could be found in npProvider.block.secret and npProvide.block.jwe respectively.
   * You need:
   *  - the data agreement. It will be parsed for correctness.
   *  - the private key of the provider. It is used to sign the proofs and to sign transactions to the ledger (if not stated otherwise)
   *  - the block of data to send as a Uint8Array
   *  - the NRP DLT agent able to publish the secret to the smart contract
   */
  const nrpProvider = new {{PKG_CAMELCASE}}.NonRepudiationProtocol.NonRepudiationOrig(dataExchangeAgreement, providerJwks.privateJwk, block, providerDltAgent)

  // Create the proof of origin (PoO)
  const poo = await nrpProvider.generatePoO()
  
  // Store PoO in the wallet
  const resource = await providerWallet.resourceCreate({
    type: 'NonRepudiationProof',
    resource: poo.jws
  })

  // Send the cipherblock in nrpProvider.block.jwe along with the poo to the consumer
  ...

  // Receive proof of reception (PoR) as a JWS and store it in variable por.
  ...

  // Verify PoR. If verification passes the por is added to npProvider.block.por; otherwise it throws an error.
  await nrpProvider.verifyPoR(por)

  // Store PoR in the wallet
  const resource = await providerWallet.resourceCreate({
    type: 'NonRepudiationProof',
    resource: por.jws
  })

  // Create proof of publication. It connects to the ledger and publishes the secret that can be used to decrypt the cipherblock
  const pop = await nrpProvider.generatePoP()

  // Store PoP in the wallet
  const resource = await providerWallet.resourceCreate({
    type: 'NonRepudiationProof',
    resource: pop.jws
  })

  // Send pop to the consumer. The PoP includes the secret to decrypt the cipherblock; although the consumer could also get the secret from the smart contract
  ...

  // It is desired to send a signed resolution about the completeness of the protocol by a trusted third party (the CRS), so generate a verification Request as:
  verificationRequest = await nrpProvider.generateVerificationRequest()

  // Send the verificationRequest to the CRS with public key stored in variable crsPublicJwk
  ...
  
  // and receive a signed resolution. The resolution can be decoded/verified as:
  const { payload } = await {{PKG_CAMELCASE}}.ConflictResolution.verifyResolution<{{PKG_CAMELCASE}}.VerificationResolutionPayload>(resolution, crsPublicKey)
  if (payload.resolution === 'completed') {
    // is a valid proof of completeness signed by signer with public key crsPublicKey
  }
)
nrp()
```

### Example for an i3-MARKET Consumer running the Non-Repudiation Protocol

Before starting the protocol you need connect with your wallet, and set up the pair of public private keys that are required for the NRP.

You can easily create the key pair with the `generateKeys` utility function:

```typescript
const consumerJwks = await {{PKG_CAMELCASE}}.generateKeys('ES256')
```

> We will assume that the consumer is using the i3-MARKET Wallet Desktop App

For connecting to the i3M-Wallet application, you need to pair first the NRP JS app with the wallet. We are using next a similar approach to [this example](https://github.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/blob/public/packages/wallet-protocol/src/docs/example/initiator-example.md):
  
```typescript
import { WalletProtocol, HttpInitiatorTransport } from '@i3m/wallet-protocol'
import { pinDialog, SessionManager } from '@i3m/wallet-protocol-utils'
import { WalletApi } from '@i3m/wallet-protocol-api'

...
// NEXT CODE IS RUN INSIDE AN ASYNC FUNCTION!
const transport = new HttpInitiatorTransport({ getConnectionString: pinDialog })

const protocol = new WalletProtocol(transport)
const sessionManager = new SessionManager({ protocol })

sessionManager
  .$session
  // We can subscribe to events when the session is deleted/end and when a new one is created
  .subscribe((session) => {
    if (session !== undefined) {
      console.log('New session loaded')
    } else {
      console.log('Session deleted')
    }
  })

// Loads the current stored session (if any). Use it to recover a previously created session
await sessionManager.loadSession()

// creates a secure session (if it does not exist yet)
await sessionManager.createIfNotExists()

// Setup the connection to the consumerWallet API
const consumerWallet = new WalletApi(sessionManager.session)

// Select an identity to use. In this example we get the one with alias set to 'consumer'
const availableIdentities = await consumerWallet.identities.list({ alias: 'consumer' })

// The consumer DID
const consumerDid = availableIdentities[0]
```

It is also assumed that consumer and provider have already agreed a [`DataSharingAgreement`](https://github.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/blob/public/packages/wallet-desktop-openapi/types/openapi.d.ts) that is stored in object variable `dataSharingAgreement` and that contains a given `DataExchangeAgreement` in `dataSharingAgreement.dataExchangeAgreement`. Go to the provider example for an in-depth explanation of the `dataExchangeAgreement`.

The agreement is stored in the consumer wallet:

```typescript
await consumerWallet.resources.create({
  type: 'Contract',
  identity: consumerDid,
  resource: {
    dataSharingAgreement,
    keyPair: {
      publicJwk: await _pkg.parseJwk(consumerJwks.publicJwk, true),
      privateJwk: await _pkg.parseJwk(consumerJwks.privateJwk, true)
    }
  }
})
```

> Notice that, contrarily to what we did with the provider, we are bounding the data sharing agreement to the consumerDid (identity), and thus wallet will also verify that this identity is the one signing as 'consumer' the agreement. It did not make sense in the provider wallet since the signer is the provider operator (who uses another wallet) and not the actual (service) provider.

And now you are ready to start a `DataExchange` for a given block of data `block` of a given `DataExchangeAgreement`.

```typescript
async nrp() => {
  const dataExchangeAgreement: {{PKG_CAMELCASE}}.DataExchangeAgreement = dataSharingAgreement.dataExchangeAgreement
  
  // Init the Consumer's agent to get published secrets from the DLT. Notice that since the consumer does not need to write to the DLT, they do not need to use a Wallet and the EthersIoAgentDest is enough
  const consumerDltAgent = new {{PKG_CAMELCASE}}.I3mWalletAgentDest(consumerWallet, dids.consumer)

  /**
   * Intialize the non-repudiation protocol as the destination of the data block.
   * You need:
   *  - the data agreement. It will be parsed for correctness.
   *  - the private key of the consumer (to sign proofs)
   *  - a NRP dest DLT Agent that is able to get from the smart contract the secret published by the provider
   */
  const nrpConsumer = new {{PKG_CAMELCASE}}.NonRepudiationProtocol.NonRepudiationDest(dataExchangeAgreement, consumerJwks.privateJwk, consumerDltAgent)

  // Receive poo and cipherblock (in JWE string format)
  ...

  // Verify PoO. If verification passes the poo is added to nrpConsumer.block.poo and cipherblock to nrpConsumer.block.cipherblock; otherwise it throws an error.
  await nrpConsumer.verifyPoO(poo.jws, cipherblock)

  // Store PoO in wallet
  await consumerWallet.resources.create({
    type: 'NonRepudiationProof',
    resource: poo.jws
  })

  // Create the proof of reception (PoR). It is also added to nrpConsumer.block.por
  const por = await nrpConsumer.generatePoR()

  // Store PoR in wallet
  await consumerWallet.resources.create({
    type: 'NonRepudiationProof',
    resource: por.jws
  })

  // Send PoR to Provider
  ...

  // Receive (or retrieve from ledger) secret as a JWK and proof of publication (PoP) as a JWS and stored them in secret and pop.
  ...

  // Verify PoP. If verification passes the pop is added to nrpConsumer.block.pop, and the secret to nrpConsumer.block.secret; otherwise it throws an error.
  await nrpConsumer.verifyPoP(pop)

  // Store PoP in wallet (if it is received)
  await consumerWallet.resources.create({
    type: 'NonRepudiationProof',
    resource: pop.jws
  })

  // Just in case the PoP is not received, the secret can be downloaded from the ledger. The next function downloads the secret and stores it to nrpConsumer.block.secret
  await nrpConsumer.getSecretFromLedger()

  // Decrypt cipherblock and verify that the hash(decrypted block) is equal to the committed one (in the original PoO). If verification fails, it throws an error.
  try {
    const decryptedBlock = await nrpConsumer.decrypt()
  } catch(error) {
    /* If we have been unable to decrypt the cipherblock using the published secret,
     * we can generate a dispute request to send to the Conflict-Resolver Service (CRS).
     */
    const disputeRequest = await nrpConsumer.generateDisputeRequest()

    // Send disputeRequest to CRS
    ...

    // We will receive a signed resolution. Let us assume that is in variable disputeResolution
    const { resolutionPayload } = await {{PKG_CAMELCASE}}.ConflictResolution.verifyResolution<{{PKG_CAMELCASE}}.DisputeResolutionPayload>(disputeResolution)
    if (resolutionPayload.resolution === 'accepted') {
      // We were right about our claim: the cipherblock cannot be decrypted and we can't be invoiced for it.
    } else { // resolutionPayload.resolution === 'denied'
      // The cipherblock can be decrypted with the published secret, so either we had a malicious intention or we have an issue with our software.
    }
  }
)
nrp()
```
