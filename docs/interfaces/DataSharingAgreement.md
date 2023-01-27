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

• **dataExchangeAgreement**: `DataExchangeAgreement`

#### Inherited from

WalletComponents.Schemas.DataSharingAgreement.dataExchangeAgreement

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:265

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

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:195

___

### dataStream

• **dataStream**: `boolean`

#### Inherited from

WalletComponents.Schemas.DataSharingAgreement.dataStream

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:245

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

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:217

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

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:222

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

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:227

___

### parties

• **parties**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `consumerDid` | `string` |
| `providerDid` | `string` |

#### Inherited from

WalletComponents.Schemas.DataSharingAgreement.parties

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:202

___

### personalData

• **personalData**: `boolean`

#### Inherited from

WalletComponents.Schemas.DataSharingAgreement.personalData

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:246

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

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:247

___

### purpose

• **purpose**: `string`

#### Inherited from

WalletComponents.Schemas.DataSharingAgreement.purpose

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:216

___

### signatures

• **signatures**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `consumerSignature` | `string` |
| `providerSignature` | `string` |

#### Inherited from

WalletComponents.Schemas.DataSharingAgreement.signatures

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:266
