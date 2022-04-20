[![License: EUPL-1.2](https://img.shields.io/badge/license-EUPL--1.2-green.svg)](LICENSE)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)
{{GITHUB_ACTIONS_BADGES}}

# {{PKG_NAME}}

Library for handling non-repudiation proofs in the i3-MARKET ecosystem. It is a core element of the Conflict Resolution system in i3-MARKET ([Read more here](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/documentation#conflict-resolution-non-repudiation-protocol)).

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

Alternatively, you can just download the [latest release](./releases/i3m-non-repudiation-library-latest.tgz) and install into your project with:

```console
npm install <path to i3m-non-repudiation-library-latest.tgz>
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

### Example for an i3-MARKET Provider using the Non-Repudiation Protocol

Before starting the agreement you need:

- **A private key for signing the non-repudiation proofs**. You should generate a public-private key pair in one of the EC supported curves (P-256, P-384, P-521). Key format must be JSON Web Key (JWK).
  
  >You can easily create the key pair with the `generateKeys` utility function. For example:
  >
  >```typescript
  >const providerJwks = await {{PKG_CAMELCASE}}.generateKeys(SIGNING_ALG)
  >```

- An Ethereum address with enough funds on the ledger and a `NrpDltAgentOrig` instance that can handle signing of the transactions needed to publish the secret to the ledger.

And now you are ready to start a `dataExchange` for a given block of a given `DataExchangeAgreement`.

```typescript
async nrp() => {
  /**
   * Using the Smart Contract Manager / Secure Data Access, a consumer and a provider would have agreed a Data Exchange Agreement
   */
  const dataExchangeAgreement: {{PKG_CAMELCASE}}.DataExchangeAgreement = {
    // Public key of the origin (data provider) for verifying the proofs she/he issues. It should be providerJwks.publicJwk
    orig: '{"kty":"EC","crv":"P-256","x":"4sxPPpsZomxPmPwDAsqSp94QpZ3iXP8xX4VxWCSCfms","y":"8YI_bvVrKPW63bGAsHgRvwXE6uj3TlnHwoQi9XaEBBE","alg":"ES256"}',
    // Public key of the destination (data consumer)
    dest: '{"kty":"EC","crv":"P-256","x":"6MGDu3EsCdEJZVV2KFhnF2lxCRI5yNpf4vWQrCIMk5M","y":"0OZbKAdooCqrQcPB3Bfqy0g-Y5SmnTyovFoFY35F00M","alg":"ES256"}',
    // Encryption algorithm used to encrypt blocks. Either AES-128-GCM ('A128GCM') or AES-256-GCM ('A256GCM)
    encAlg: 'A256GCM',
    // Signing algorithm used to sign the proofs. It'e ECDSA secp256r1 with key lengths: either 'ES256', 'ES384', or 'ES512' 
    signingAlg: 'ES256',
    // Hash algorith used to compute digest/commitments. It's SHA2 with different output lengths: either 'SHA-256', 'SHA-384' or 'SHA-512'
    hashAlg: 'SHA-256',
    // The ledger smart contract address (hexadecimal) on the DLT
    ledgerContractAddress: '0x7B7C7c0c8952d1BDB7E4D90B1B7b7C48c13355D1',
    // The orig (data provider) address in the DLT (hexadecimal).
    ledgerSignerAddress: '0x17bd12C2134AfC1f6E9302a532eFE30C19B9E903',
    // Maximum acceptable delay between the issuance of the proof of origing (PoO) by the orig and the reception of the proof of reception (PoR) by the orig
    pooToPorDelay: 10000,
    // Maximum acceptable delay between the issuance of the proof of origing (PoP) by the orig and the reception of the proof of publication (PoR) by the dest
    pooToPopDelay: 20000,
    // If the dest (data consumer) does not receive the PoP, it could still get the decryption secret from the DLT. This defines the maximum acceptable delay between the issuance of the proof of origing (PoP) by the orig and the publication (block time) of the secret on the blockchain.
    pooToSecretDelay: 150000
  }

  // Let us define the RPC endopint to the ledger
  const dltConfig: Partial<{{PKG_CAMELCASE}}.DltConfig> = {
    rpcProviderUrl: 'http://89.111.35.214:8545'
  }
  
  // We are going to directly provide the private key associated to the dataExchange.ledgerSignerAddress. You could also have pass a DltSigner instance to dltConfig.signer in order to use an external Wallet, such as the i3-MARKET one
  const providerDltSigningKeyHex = '0x4b7903c8fe18e4ba5329939c7d1c4318307794a544f3eb5fb3b6536210c98676'

  // Create a NRP DLT Agent for the provider. We are going to use the Ethers.io one
  providerDltAgent = new {{PKG_CAMELCASE}}.EthersIoAgentOrig(dltConfig, providerDltSigningKeyHex)

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
  
  // Send the cipherblock in nrpProvider.block.jwe along with the poo to the consumer
  ...

  // Receive proof of reception (PoR) as a JWS and store it in variable por.
  ...

  // Verify PoR. If verification passes the por is added to npProvider.block.por; otherwise it throws an error.
  await nrpProvider.verifyPoR(por)

  // Create proof of publication. It connects to the ledger and publishes the secret that can be used to decrypt the cipherblock
  const pop = await nrpProvider.generatePoP()

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

### Example for an i3-MARKET Consumer using the Non-Repudiation Protocol

Before starting the agreement, you need a pair of public private keys. You can easily create the key pair with the `generateKeys` utility function:

```typescript
  const consumerJwks = await {{PKG_CAMELCASE}}.generateKeys('ES256')
```

And now you are ready to start a `DataExchange` for a given block of a given `DataExchangeAgreement`.

```typescript
async nrp() => {
  /**
   * Using the Smart Contract Manager / Secure Data Access, a consumer and a provider would have agreed a Data Exchange Agreement
   */
  const dataExchangeAgreement: {{PKG_CAMELCASE}}.DataExchangeAgreement = {
    // Public key of the origin (data provider)
    orig: '{"kty":"EC","crv":"P-256","x":"4sxPPpsZomxPmPwDAsqSp94QpZ3iXP8xX4VxWCSCfms","y":"8YI_bvVrKPW63bGAsHgRvwXE6uj3TlnHwoQi9XaEBBE","alg":"ES256"}',
    // Public key of the destination (data consumer). It should be consumerJwks.publicJwk
    dest: '{"kty":"EC","crv":"P-256","x":"6MGDu3EsCdEJZVV2KFhnF2lxCRI5yNpf4vWQrCIMk5M","y":"0OZbKAdooCqrQcPB3Bfqy0g-Y5SmnTyovFoFY35F00M","alg":"ES256"}',
    // Encryption algorithm used to encrypt blocks. Either AES-128-GCM ('A128GCM') or AES-256-GCM ('A256GCM)
    encAlg: 'A256GCM',
    // Signing algorithm used to sign the proofs. It'e ECDSA secp256r1 with key lengths: either 'ES256', 'ES384', or 'ES512' 
    signingAlg: 'ES256',
    // Hash algorith used to compute digest/commitments. It's SHA2 with different output lengths: either 'SHA-256', 'SHA-384' or 'SHA-512'
    hashAlg: 'SHA-256',
    // The ledger smart contract address on the DLT (hexadecimal)
    ledgerContractAddress: '0x7b7c7c0c8952d1bdb7e4d90b1b7b7c48c13355d1',
    // The orig (data provider) address in the DLT (hexadecimal). It can use a different keypair for signing proofs and signing transactions to the DLT) 
    ledgerSignerAddress: '0x17bd12c2134afc1f6e9302a532efe30c19b9e903',
    // Maximum acceptable delay between the issuance of the proof of origing (PoO) by the orig and the reception of the proof of reception (PoR) by the orig
    pooToPorDelay: 10000,
    // Maximum acceptable delay between the issuance of the proof of origing (PoP) by the orig and the reception of the proof of publication (PoR) by the dest
    pooToPopDelay: 20000,
    // If the dest (data consumer) does not receive the PoP, it could still get the decryption secret from the DLT. This defines the maximum acceptable delay between the issuance of the proof of origing (PoP) by the orig and the publication (block time) of the secret on the blockchain.
    pooToSecretDelay: 180000
  }
  
  // Let us define the RPC endopint to the ledger
  const dltConfig: Partial<{{PKG_CAMELCASE}}.DltConfig> = {
    rpcProviderUrl: 'http://89.111.35.214:8545'
  }

  // Init the Consumer's agent to get published secrets from the DLT.
  consumerDltAgent = new {{PKG_CAMELCASE}}.EthersIoAgentDest(dltConfig)

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
  
  // Create the proof of reception (PoR). It is also added to nrpConsumer.block.por
  const por = await nrpConsumer.generatePoR()

  // Send PoR to Provider
  ...

  // Receive (or retrieve from ledger) secret as a JWK and proof of publication (PoP) as a JWS and stored them in secret and pop.
  ...

  // Verify PoP. If verification passes the pop is added to nrpConsumer.block.pop, and the secret to nrpConsumer.block.secret; otherwise it throws an error.
  await nrpConsumer.verifyPoP(pop)

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
