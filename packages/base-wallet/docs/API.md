# @i3m/base-wallet - v2.2.2

## Table of contents

### Classes

- [BaseWallet](classes/BaseWallet.md)
- [ConsoleToast](classes/ConsoleToast.md)
- [FileStore](classes/FileStore.md)
- [NullDialog](classes/NullDialog.md)
- [RamStore](classes/RamStore.md)
- [TestDialog](classes/TestDialog.md)
- [TestStore](classes/TestStore.md)
- [TestToast](classes/TestToast.md)
- [Veramo](classes/Veramo.md)
- [WalletError](classes/WalletError.md)

### Interfaces

- [BaseDialogOptions](interfaces/BaseDialogOptions.md)
- [BaseWalletModel](interfaces/BaseWalletModel.md)
- [ConfirmationOptions](interfaces/ConfirmationOptions.md)
- [Dialog](interfaces/Dialog.md)
- [FormOptions](interfaces/FormOptions.md)
- [KeyWallet](interfaces/KeyWallet.md)
- [SelectOptions](interfaces/SelectOptions.md)
- [Store](interfaces/Store.md)
- [TextOptions](interfaces/TextOptions.md)
- [Toast](interfaces/Toast.md)
- [ToastOptions](interfaces/ToastOptions.md)
- [Wallet](interfaces/Wallet.md)
- [WalletFunctionMetadata](interfaces/WalletFunctionMetadata.md)
- [WalletMetadata](interfaces/WalletMetadata.md)
- [WalletOptionsCryptoWallet](interfaces/WalletOptionsCryptoWallet.md)
- [WalletOptionsSettings](interfaces/WalletOptionsSettings.md)

### Type Aliases

- [CanBePromise](API.md#canbepromise)
- [Contract](API.md#contract)
- [ContractResource](API.md#contractresource)
- [DataExchangeResource](API.md#dataexchangeresource)
- [Descriptors](API.md#descriptors)
- [DescriptorsMap](API.md#descriptorsmap)
- [DialogOptionContext](API.md#dialogoptioncontext)
- [DialogResponse](API.md#dialogresponse)
- [Identity](API.md#identity)
- [KeyLike](API.md#keylike)
- [NonRepudiationProofResource](API.md#nonrepudiationproofresource)
- [Object](API.md#object)
- [ObjectResource](API.md#objectresource)
- [ProviderData](API.md#providerdata)
- [Resource](API.md#resource)
- [ToastType](API.md#toasttype)
- [TypedArray](API.md#typedarray)
- [VerifiableCredential](API.md#verifiablecredential)
- [VerifiableCredentialResource](API.md#verifiablecredentialresource)
- [WalletBuilder](API.md#walletbuilder)
- [WalletOptions](API.md#walletoptions)

### Variables

- [base64url](API.md#base64url)

### Functions

- [didJwtVerify](API.md#didjwtverify)
- [getCredentialClaims](API.md#getcredentialclaims)
- [jwkSecret](API.md#jwksecret)
- [parseAddress](API.md#parseaddress)
- [parseHex](API.md#parsehex)
- [verifyDataSharingAgreementSignature](API.md#verifydatasharingagreementsignature)

## Type Aliases

### CanBePromise

Ƭ **CanBePromise**<`T`\>: `Promise`<`T`\> \| `T`

#### Type parameters

| Name |
| :------ |
| `T` |

#### Defined in

[base-wallet/src/ts/utils/types.ts:1](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/utils/types.ts#L1)

___

### Contract

Ƭ **Contract**: `WalletComponents.Schemas.Contract`[``"resource"``]

#### Defined in

[base-wallet/src/ts/app/store.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/app/store.ts#L13)

___

### ContractResource

Ƭ **ContractResource**: [`Resource`](API.md#resource) & { `type`: ``"Contract"``  }

#### Defined in

[base-wallet/src/ts/app/store.ts:8](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/app/store.ts#L8)

___

### DataExchangeResource

Ƭ **DataExchangeResource**: [`Resource`](API.md#resource) & { `type`: ``"DataExchange"``  }

#### Defined in

[base-wallet/src/ts/app/store.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/app/store.ts#L10)

___

### Descriptors

Ƭ **Descriptors**<`T`\>: `TextFormDescriptor` \| `ConfirmationFormDescriptor` \| `SelectFormDescriptor`<`T`\>

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | `any` |

#### Defined in

[base-wallet/src/ts/app/dialog.ts:42](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/app/dialog.ts#L42)

___

### DescriptorsMap

Ƭ **DescriptorsMap**<`T`\>: { [K in keyof Partial<T\>]: Descriptors<T[K]\> }

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | `any` |

#### Defined in

[base-wallet/src/ts/app/dialog.ts:43](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/app/dialog.ts#L43)

___

### DialogOptionContext

Ƭ **DialogOptionContext**: ``"success"`` \| ``"danger"``

#### Defined in

[base-wallet/src/ts/app/dialog.ts:40](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/app/dialog.ts#L40)

___

### DialogResponse

Ƭ **DialogResponse**<`T`\>: `Promise`<`T` \| `undefined`\>

#### Type parameters

| Name |
| :------ |
| `T` |

#### Defined in

[base-wallet/src/ts/app/dialog.ts:52](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/app/dialog.ts#L52)

___

### Identity

Ƭ **Identity**: `IIdentifier`

#### Defined in

[base-wallet/src/ts/app/store.ts:15](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/app/store.ts#L15)

___

### KeyLike

Ƭ **KeyLike**: `Uint8Array`

#### Defined in

[base-wallet/src/ts/utils/types.ts:5](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/utils/types.ts#L5)

___

### NonRepudiationProofResource

Ƭ **NonRepudiationProofResource**: [`Resource`](API.md#resource) & { `type`: ``"NonRepudiationProof"``  }

#### Defined in

[base-wallet/src/ts/app/store.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/app/store.ts#L9)

___

### Object

Ƭ **Object**: `WalletComponents.Schemas.ObjectResource`[``"resource"``]

#### Defined in

[base-wallet/src/ts/app/store.ts:14](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/app/store.ts#L14)

___

### ObjectResource

Ƭ **ObjectResource**: [`Resource`](API.md#resource) & { `type`: ``"Object"``  }

#### Defined in

[base-wallet/src/ts/app/store.ts:7](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/app/store.ts#L7)

___

### ProviderData

Ƭ **ProviderData**: `Omit`<`ConstructorParameters`<typeof `EthrDIDProvider`\>[``0``], ``"defaultKms"``\>

#### Defined in

[base-wallet/src/ts/veramo/veramo.ts:39](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/veramo/veramo.ts#L39)

___

### Resource

Ƭ **Resource**: `WalletComponents.Schemas.Resource` & `WalletComponents.Schemas.ResourceId` & { `identity?`: `WalletComponents.Schemas.ObjectResource`[``"identity"``]  } & { `parentResource?`: `WalletComponents.Schemas.ObjectResource`[``"parentResource"``]  }

#### Defined in

[base-wallet/src/ts/app/store.ts:5](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/app/store.ts#L5)

___

### ToastType

Ƭ **ToastType**: ``"info"`` \| ``"success"`` \| ``"warning"`` \| ``"error"``

#### Defined in

[base-wallet/src/ts/app/toast.ts:2](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/app/toast.ts#L2)

___

### TypedArray

Ƭ **TypedArray**: `Int8Array` \| `Uint8Array` \| `Uint8ClampedArray` \| `Int16Array` \| `Uint16Array` \| `Int32Array` \| `Uint32Array` \| `Float32Array` \| `Float64Array` \| `BigInt64Array` \| `BigUint64Array`

#### Defined in

[base-wallet/src/ts/utils/types.ts:3](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/utils/types.ts#L3)

___

### VerifiableCredential

Ƭ **VerifiableCredential**: `WalletComponents.Schemas.VerifiableCredential`[``"resource"``]

#### Defined in

[base-wallet/src/ts/app/store.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/app/store.ts#L12)

___

### VerifiableCredentialResource

Ƭ **VerifiableCredentialResource**: [`Resource`](API.md#resource) & { `type`: ``"VerifiableCredential"``  }

#### Defined in

[base-wallet/src/ts/app/store.ts:6](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/app/store.ts#L6)

___

### WalletBuilder

Ƭ **WalletBuilder**<`Options`\>: (`opts`: `Options`) => `Promise`<[`Wallet`](interfaces/Wallet.md)\>

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Options` | extends [`WalletOptionsSettings`](interfaces/WalletOptionsSettings.md)<`any`\> |

#### Type declaration

▸ (`opts`): `Promise`<[`Wallet`](interfaces/Wallet.md)\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `opts` | `Options` |

##### Returns

`Promise`<[`Wallet`](interfaces/Wallet.md)\>

#### Defined in

[base-wallet/src/ts/wallet/wallet-builder.ts:4](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/wallet/wallet-builder.ts#L4)

___

### WalletOptions

Ƭ **WalletOptions**<`T`\>: [`WalletOptionsSettings`](interfaces/WalletOptionsSettings.md)<`T`\> & [`WalletOptionsCryptoWallet`](interfaces/WalletOptionsCryptoWallet.md)

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends [`BaseWalletModel`](interfaces/BaseWalletModel.md) |

#### Defined in

[base-wallet/src/ts/wallet/wallet-options.ts:16](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/wallet/wallet-options.ts#L16)

## Variables

### base64url

• **base64url**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `decode` | (`str`: `string`) => `Buffer` |
| `encode` | (`buf`: `Buffer`) => `string` |

#### Defined in

[base-wallet/src/ts/utils/base64url.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/utils/base64url.ts#L9)

## Functions

### didJwtVerify

▸ **didJwtVerify**(`jwt`, `veramo`, `expectedPayloadClaims?`): `Promise`<`WalletPaths.DidJwtVerify.Responses.$200`\>

Verifies a JWT resolving the public key from the signer DID (no other kind of signer supported) and optionally check values for expected payload claims.

The Wallet only supports the 'ES256K1' algorithm.

Useful to verify JWT created by another wallet instance.

#### Parameters

| Name | Type |
| :------ | :------ |
| `jwt` | `string` |
| `veramo` | [`Veramo`](classes/Veramo.md)<[`BaseWalletModel`](interfaces/BaseWalletModel.md)\> |
| `expectedPayloadClaims?` | `any` |

#### Returns

`Promise`<`WalletPaths.DidJwtVerify.Responses.$200`\>

#### Defined in

[base-wallet/src/ts/utils/did-jwt-verify.ts:20](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/utils/did-jwt-verify.ts#L20)

___

### getCredentialClaims

▸ **getCredentialClaims**(`vc`): `string`[]

#### Parameters

| Name | Type |
| :------ | :------ |
| `vc` | `VerifiableCredential` |

#### Returns

`string`[]

#### Defined in

[base-wallet/src/ts/utils/credential-claims.ts:3](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/utils/credential-claims.ts#L3)

___

### jwkSecret

▸ **jwkSecret**(`secret?`): `SecretJwk`

#### Parameters

| Name | Type |
| :------ | :------ |
| `secret` | `Buffer` |

#### Returns

`SecretJwk`

#### Defined in

[base-wallet/src/ts/utils/generate-secret.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/utils/generate-secret.ts#L11)

___

### parseAddress

▸ **parseAddress**(`a`): `string`

Verifies and returns an ethereum address

#### Parameters

| Name | Type |
| :------ | :------ |
| `a` | `string` |

#### Returns

`string`

#### Defined in

[base-wallet/src/ts/utils/parseAddress.ts:7](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/utils/parseAddress.ts#L7)

___

### parseHex

▸ **parseHex**(`a`, `prefix0x?`): `string`

Verifies an hexadecimal string and returns it with (default) or without 0x prefix

#### Parameters

| Name | Type | Default value |
| :------ | :------ | :------ |
| `a` | `string` | `undefined` |
| `prefix0x` | `boolean` | `true` |

#### Returns

`string`

#### Defined in

[base-wallet/src/ts/utils/parseHex.ts:7](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/utils/parseHex.ts#L7)

___

### verifyDataSharingAgreementSignature

▸ **verifyDataSharingAgreementSignature**(`agreement`, `veramo`, `signer`): `Promise`<`Error`[]\>

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `agreement` | `Object` | - |
| `agreement.dataExchangeAgreement` | `Object` | - |
| `agreement.dataExchangeAgreement.dest` | `string` | A stringified JWK with alphabetically sorted claims example: {"alg":"ES256","crv":"P-256","kty":"EC","x":"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k","y":"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4"} |
| `agreement.dataExchangeAgreement.encAlg` | ``"A128GCM"`` \| ``"A256GCM"`` | example: A256GCM |
| `agreement.dataExchangeAgreement.hashAlg` | ``"SHA-256"`` \| ``"SHA-384"`` \| ``"SHA-512"`` | example: SHA-256 |
| `agreement.dataExchangeAgreement.ledgerContractAddress` | `string` | Ethereum Address in EIP-55 format (with checksum) example: 0x71C7656EC7ab88b098defB751B7401B5f6d8976F |
| `agreement.dataExchangeAgreement.ledgerSignerAddress` | `string` | Ethereum Address in EIP-55 format (with checksum) example: 0x71C7656EC7ab88b098defB751B7401B5f6d8976F |
| `agreement.dataExchangeAgreement.orig` | `string` | A stringified JWK with alphabetically sorted claims example: {"alg":"ES256","crv":"P-256","kty":"EC","x":"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo","y":"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0"} |
| `agreement.dataExchangeAgreement.pooToPopDelay` | `number` | Maximum acceptable time in milliseconds between issued PoO and issued PoP example: 20000 |
| `agreement.dataExchangeAgreement.pooToPorDelay` | `number` | Maximum acceptable time in milliseconds between issued PoO and verified PoR example: 10000 |
| `agreement.dataExchangeAgreement.pooToSecretDelay` | `number` | Maximum acceptable time between issued PoO and secret published on the ledger example: 180000 |
| `agreement.dataExchangeAgreement.schema?` | `string` | A stringified JSON-LD schema describing the data format |
| `agreement.dataExchangeAgreement.signingAlg` | ``"ES256"`` \| ``"ES384"`` \| ``"ES512"`` | example: ES256 |
| `agreement.dataOfferingDescription` | `Object` | - |
| `agreement.dataOfferingDescription.active` | `boolean` | - |
| `agreement.dataOfferingDescription.category?` | `string` | - |
| `agreement.dataOfferingDescription.dataOfferingId` | `string` | - |
| `agreement.dataOfferingDescription.title?` | `string` | - |
| `agreement.dataOfferingDescription.version` | `number` | - |
| `agreement.dataStream` | `boolean` | - |
| `agreement.duration` | `Object` | - |
| `agreement.duration.creationDate` | `number` | - |
| `agreement.duration.endDate` | `number` | - |
| `agreement.duration.startDate` | `number` | - |
| `agreement.intendedUse` | `Object` | - |
| `agreement.intendedUse.editData` | `boolean` | - |
| `agreement.intendedUse.processData` | `boolean` | - |
| `agreement.intendedUse.shareDataWithThirdParty` | `boolean` | - |
| `agreement.licenseGrant` | `Object` | - |
| `agreement.licenseGrant.analyzing` | `boolean` | - |
| `agreement.licenseGrant.distributing` | `boolean` | - |
| `agreement.licenseGrant.exclusiveness` | `boolean` | - |
| `agreement.licenseGrant.furtherLicensing` | `boolean` | - |
| `agreement.licenseGrant.leasing` | `boolean` | - |
| `agreement.licenseGrant.loaning` | `boolean` | - |
| `agreement.licenseGrant.modifying` | `boolean` | - |
| `agreement.licenseGrant.paidUp` | `boolean` | - |
| `agreement.licenseGrant.processing` | `boolean` | - |
| `agreement.licenseGrant.renting` | `boolean` | - |
| `agreement.licenseGrant.reproducing` | `boolean` | - |
| `agreement.licenseGrant.revocable` | `boolean` | - |
| `agreement.licenseGrant.selling` | `boolean` | - |
| `agreement.licenseGrant.storingCopy` | `boolean` | - |
| `agreement.licenseGrant.storingData` | `boolean` | - |
| `agreement.licenseGrant.transferable` | `boolean` | - |
| `agreement.parties` | `Object` | - |
| `agreement.parties.consumerDid` | `string` | a DID using the ethr resolver example: did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863 |
| `agreement.parties.providerDid` | `string` | a DID using the ethr resolver example: did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863 |
| `agreement.personalData` | `boolean` | - |
| `agreement.pricingModel` | `Object` | - |
| `agreement.pricingModel.basicPrice` | `number` | - |
| `agreement.pricingModel.currency` | `string` | - |
| `agreement.pricingModel.fee?` | `number` | - |
| `agreement.pricingModel.hasFreePrice` | `Object` | - |
| `agreement.pricingModel.hasFreePrice.hasPriceFree?` | `boolean` | - |
| `agreement.pricingModel.hasPaymentOnSubscription?` | `Object` | - |
| `agreement.pricingModel.hasPaymentOnSubscription.description?` | `string` | - |
| `agreement.pricingModel.hasPaymentOnSubscription.hasSubscriptionPrice?` | `number` | - |
| `agreement.pricingModel.hasPaymentOnSubscription.paymentOnSubscriptionName?` | `string` | - |
| `agreement.pricingModel.hasPaymentOnSubscription.paymentType?` | `string` | - |
| `agreement.pricingModel.hasPaymentOnSubscription.repeat?` | `string` | - |
| `agreement.pricingModel.hasPaymentOnSubscription.timeDuration?` | `string` | - |
| `agreement.pricingModel.paymentType?` | `string` | - |
| `agreement.pricingModel.pricingModelName?` | `string` | - |
| `agreement.purpose` | `string` | - |
| `agreement.signatures` | `Object` | - |
| `agreement.signatures.consumerSignature` | `string` | CompactJWS |
| `agreement.signatures.providerSignature` | `string` | CompactJWS |
| `veramo` | [`Veramo`](classes/Veramo.md)<[`BaseWalletModel`](interfaces/BaseWalletModel.md)\> | - |
| `signer` | ``"provider"`` \| ``"consumer"`` | - |

#### Returns

`Promise`<`Error`[]\>

#### Defined in

[base-wallet/src/ts/utils/data-sharing-agreement-validation.ts:6](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fb538ee/packages/base-wallet/src/ts/utils/data-sharing-agreement-validation.ts#L6)
