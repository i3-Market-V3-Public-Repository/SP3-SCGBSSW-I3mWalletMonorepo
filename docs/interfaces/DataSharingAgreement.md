# Interface: DataSharingAgreement

## Hierarchy

- `DataSharingAgreement`

  ↳ **`DataSharingAgreement`**

## Table of contents

### Properties

- [dataExchangeAgreement](DataSharingAgreement.md#dataexchangeagreement)
- [dataOfferingDescription](DataSharingAgreement.md#dataofferingdescription)
- [dataStream](DataSharingAgreement.md#datastream)
- [duration](DataSharingAgreement.md#duration)
- [intendedUse](DataSharingAgreement.md#intendeduse)
- [licenseGrant](DataSharingAgreement.md#licensegrant)
- [parties](DataSharingAgreement.md#parties)
- [personalData](DataSharingAgreement.md#personaldata)
- [pricingModel](DataSharingAgreement.md#pricingmodel)
- [purpose](DataSharingAgreement.md#purpose)
- [signatures](DataSharingAgreement.md#signatures)

## Properties

### dataExchangeAgreement

• **dataExchangeAgreement**: `Object`

#### Type declaration

| Name | Type | Description |
| :------ | :------ | :------ |
| `dest` | `string` | A stringified JWK with alphabetically sorted claims example: {"alg":"ES256","crv":"P-256","kty":"EC","x":"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k","y":"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4"} |
| `encAlg` | ``"A128GCM"`` \| ``"A256GCM"`` | example: A256GCM |
| `hashAlg` | ``"SHA-256"`` \| ``"SHA-384"`` \| ``"SHA-512"`` | example: SHA-256 |
| `ledgerContractAddress` | `string` | Ethereum Address in EIP-55 format (with checksum) example: 0x71C7656EC7ab88b098defB751B7401B5f6d8976F |
| `ledgerSignerAddress` | `string` | Ethereum Address in EIP-55 format (with checksum) example: 0x71C7656EC7ab88b098defB751B7401B5f6d8976F |
| `orig` | `string` | A stringified JWK with alphabetically sorted claims example: {"alg":"ES256","crv":"P-256","kty":"EC","x":"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo","y":"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0"} |
| `pooToPopDelay` | `number` | Maximum acceptable time in milliseconds between issued PoO and issued PoP example: 20000 |
| `pooToPorDelay` | `number` | Maximum acceptable time in milliseconds between issued PoO and verified PoR example: 10000 |
| `pooToSecretDelay` | `number` | Maximum acceptable time between issued PoO and secret published on the ledger example: 180000 |
| `schema?` | `string` | A stringified JSON-LD schema describing the data format |
| `signingAlg` | ``"ES256"`` \| ``"ES384"`` \| ``"ES512"`` | example: ES256 |

#### Inherited from

WalletComponents.Schemas.DataSharingAgreement.dataExchangeAgreement

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:498

___

### dataOfferingDescription

• **dataOfferingDescription**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `active` | `boolean` |
| `category?` | `string` |
| `dataOfferingId` | `string` |
| `title?` | `string` |
| `version` | `number` |

#### Inherited from

WalletComponents.Schemas.DataSharingAgreement.dataOfferingDescription

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:428

___

### dataStream

• **dataStream**: `boolean`

#### Inherited from

WalletComponents.Schemas.DataSharingAgreement.dataStream

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:478

___

### duration

• **duration**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `creationDate` | `number` |
| `endDate` | `number` |
| `startDate` | `number` |

#### Inherited from

WalletComponents.Schemas.DataSharingAgreement.duration

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:450

___

### intendedUse

• **intendedUse**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `editData` | `boolean` |
| `processData` | `boolean` |
| `shareDataWithThirdParty` | `boolean` |

#### Inherited from

WalletComponents.Schemas.DataSharingAgreement.intendedUse

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:455

___

### licenseGrant

• **licenseGrant**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `analyzing` | `boolean` |
| `distributing` | `boolean` |
| `exclusiveness` | `boolean` |
| `furtherLicensing` | `boolean` |
| `leasing` | `boolean` |
| `loaning` | `boolean` |
| `modifying` | `boolean` |
| `paidUp` | `boolean` |
| `processing` | `boolean` |
| `renting` | `boolean` |
| `reproducing` | `boolean` |
| `revocable` | `boolean` |
| `selling` | `boolean` |
| `storingCopy` | `boolean` |
| `storingData` | `boolean` |
| `transferable` | `boolean` |

#### Inherited from

WalletComponents.Schemas.DataSharingAgreement.licenseGrant

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:460

___

### parties

• **parties**: `Object`

#### Type declaration

| Name | Type | Description |
| :------ | :------ | :------ |
| `consumerDid` | `string` | a DID using the ethr resolver example: did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863 |
| `providerDid` | `string` | a DID using the ethr resolver example: did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863 |

#### Inherited from

WalletComponents.Schemas.DataSharingAgreement.parties

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:435

___

### personalData

• **personalData**: `boolean`

#### Inherited from

WalletComponents.Schemas.DataSharingAgreement.personalData

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:479

___

### pricingModel

• **pricingModel**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `basicPrice` | `number` |
| `currency` | `string` |
| `fee?` | `number` |
| `hasFreePrice` | { `hasPriceFree?`: `boolean`  } |
| `hasFreePrice.hasPriceFree?` | `boolean` |
| `hasPaymentOnSubscription?` | { `description?`: `string` ; `hasSubscriptionPrice?`: `number` ; `paymentOnSubscriptionName?`: `string` ; `paymentType?`: `string` ; `repeat?`: `string` ; `timeDuration?`: `string`  } |
| `hasPaymentOnSubscription.description?` | `string` |
| `hasPaymentOnSubscription.hasSubscriptionPrice?` | `number` |
| `hasPaymentOnSubscription.paymentOnSubscriptionName?` | `string` |
| `hasPaymentOnSubscription.paymentType?` | `string` |
| `hasPaymentOnSubscription.repeat?` | `string` |
| `hasPaymentOnSubscription.timeDuration?` | `string` |
| `paymentType?` | `string` |
| `pricingModelName?` | `string` |

#### Inherited from

WalletComponents.Schemas.DataSharingAgreement.pricingModel

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:480

___

### purpose

• **purpose**: `string`

#### Inherited from

WalletComponents.Schemas.DataSharingAgreement.purpose

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:449

___

### signatures

• **signatures**: `Object`

#### Type declaration

| Name | Type | Description |
| :------ | :------ | :------ |
| `consumerSignature` | `string` | CompactJWS |
| `providerSignature` | `string` | CompactJWS |

#### Inherited from

WalletComponents.Schemas.DataSharingAgreement.signatures

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:561
