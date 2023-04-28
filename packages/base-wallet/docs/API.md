# @i3m/base-wallet - v2.5.11

## Table of contents

### References

- [RamStore](API.md#ramstore)

### Classes

- [BaseWallet](classes/BaseWallet.md)
- [ConsoleToast](classes/ConsoleToast.md)
- [FileStore](classes/FileStore.md)
- [NullDialog](classes/NullDialog.md)
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
- [KdfOptions](interfaces/KdfOptions.md)
- [KeyWallet](interfaces/KeyWallet.md)
- [MultipleExecutionsOptions](interfaces/MultipleExecutionsOptions.md)
- [ProviderData](interfaces/ProviderData.md)
- [ScryptOptions](interfaces/ScryptOptions.md)
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
- [KeyPair](API.md#keypair)
- [KeyPairResource](API.md#keypairresource)
- [MultipleExecutionsReturn](API.md#multipleexecutionsreturn)
- [NonRepudiationProofResource](API.md#nonrepudiationproofresource)
- [Object](API.md#object)
- [ObjectResource](API.md#objectresource)
- [Resource](API.md#resource)
- [ToastType](API.md#toasttype)
- [TypedArray](API.md#typedarray)
- [VerifiableCredential](API.md#verifiablecredential)
- [VerifiableCredentialResource](API.md#verifiablecredentialresource)
- [WalletBuilder](API.md#walletbuilder)
- [WalletOptions](API.md#walletoptions)

### Variables

- [DEFAULT\_PROVIDER](API.md#default_provider)
- [DEFAULT\_PROVIDERS\_DATA](API.md#default_providers_data)
- [base64url](API.md#base64url)

### Functions

- [deriveKey](API.md#derivekey)
- [didJwtVerify](API.md#didjwtverify)
- [getCredentialClaims](API.md#getcredentialclaims)
- [jwkSecret](API.md#jwksecret)
- [multipleExecutions](API.md#multipleexecutions)
- [parseAddress](API.md#parseaddress)
- [parseHex](API.md#parsehex)
- [verifyDataSharingAgreementSignature](API.md#verifydatasharingagreementsignature)

## References

### RamStore

Renames and re-exports [TestStore](classes/TestStore.md)

## Type Aliases

### CanBePromise

Ƭ **CanBePromise**<`T`\>: `Promise`<`T`\> \| `T`

#### Type parameters

| Name |
| :------ |
| `T` |

#### Defined in

[src/ts/utils/types.ts:1](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/utils/types.ts#L1)

___

### Contract

Ƭ **Contract**: `WalletComponents.Schemas.Contract`[``"resource"``]

#### Defined in

[src/ts/app/store.ts:17](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/app/store.ts#L17)

___

### ContractResource

Ƭ **ContractResource**: [`Resource`](API.md#resource) & { `type`: ``"Contract"``  }

#### Defined in

[src/ts/app/store.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/app/store.ts#L11)

___

### DataExchangeResource

Ƭ **DataExchangeResource**: [`Resource`](API.md#resource) & { `type`: ``"DataExchange"``  }

#### Defined in

[src/ts/app/store.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/app/store.ts#L13)

___

### Descriptors

Ƭ **Descriptors**<`T`\>: `TextFormDescriptor` \| `ConfirmationFormDescriptor` \| `SelectFormDescriptor`<`T`\>

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | `any` |

#### Defined in

[src/ts/app/dialog.ts:42](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/app/dialog.ts#L42)

___

### DescriptorsMap

Ƭ **DescriptorsMap**<`T`\>: { [K in keyof Partial<T\>]: Descriptors<T[K]\> }

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | `any` |

#### Defined in

[src/ts/app/dialog.ts:43](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/app/dialog.ts#L43)

___

### DialogOptionContext

Ƭ **DialogOptionContext**: ``"success"`` \| ``"danger"``

#### Defined in

[src/ts/app/dialog.ts:40](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/app/dialog.ts#L40)

___

### DialogResponse

Ƭ **DialogResponse**<`T`\>: `Promise`<`T` \| `undefined`\>

#### Type parameters

| Name |
| :------ |
| `T` |

#### Defined in

[src/ts/app/dialog.ts:52](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/app/dialog.ts#L52)

___

### Identity

Ƭ **Identity**: `IIdentifier`

#### Defined in

[src/ts/app/store.ts:19](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/app/store.ts#L19)

___

### KeyLike

Ƭ **KeyLike**: `Uint8Array`

#### Defined in

[src/ts/utils/types.ts:5](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/utils/types.ts#L5)

___

### KeyPair

Ƭ **KeyPair**: `WalletComponents.Schemas.KeyPair`[``"resource"``]

#### Defined in

[src/ts/app/store.ts:16](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/app/store.ts#L16)

___

### KeyPairResource

Ƭ **KeyPairResource**: [`Resource`](API.md#resource) & { `type`: ``"KeyPair"``  }

#### Defined in

[src/ts/app/store.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/app/store.ts#L10)

___

### MultipleExecutionsReturn

Ƭ **MultipleExecutionsReturn**<`K`, `T`\>: `ValueOrResolvedValue`<`ReturnType`<`T`[`K`]\>\>

#### Type parameters

| Name | Type |
| :------ | :------ |
| `K` | extends `string` |
| `T` | extends `FunctionMap`<`K`\> |

#### Defined in

[src/ts/utils/multiple-executions.ts:17](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/utils/multiple-executions.ts#L17)

___

### NonRepudiationProofResource

Ƭ **NonRepudiationProofResource**: [`Resource`](API.md#resource) & { `type`: ``"NonRepudiationProof"``  }

#### Defined in

[src/ts/app/store.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/app/store.ts#L12)

___

### Object

Ƭ **Object**: `WalletComponents.Schemas.ObjectResource`[``"resource"``]

#### Defined in

[src/ts/app/store.ts:18](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/app/store.ts#L18)

___

### ObjectResource

Ƭ **ObjectResource**: [`Resource`](API.md#resource) & { `type`: ``"Object"``  }

#### Defined in

[src/ts/app/store.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/app/store.ts#L9)

___

### Resource

Ƭ **Resource**: `WalletComponents.Schemas.Resource` & `WalletComponents.Schemas.ResourceId` & { `identity?`: `WalletComponents.Schemas.ObjectResource`[``"identity"``]  } & { `parentResource?`: `WalletComponents.Schemas.ObjectResource`[``"parentResource"``]  }

#### Defined in

[src/ts/app/store.ts:7](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/app/store.ts#L7)

___

### ToastType

Ƭ **ToastType**: ``"info"`` \| ``"success"`` \| ``"warning"`` \| ``"error"``

#### Defined in

[src/ts/app/toast.ts:2](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/app/toast.ts#L2)

___

### TypedArray

Ƭ **TypedArray**: `Int8Array` \| `Uint8Array` \| `Uint8ClampedArray` \| `Int16Array` \| `Uint16Array` \| `Int32Array` \| `Uint32Array` \| `Float32Array` \| `Float64Array` \| `BigInt64Array` \| `BigUint64Array`

#### Defined in

[src/ts/utils/types.ts:3](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/utils/types.ts#L3)

___

### VerifiableCredential

Ƭ **VerifiableCredential**: `WalletComponents.Schemas.VerifiableCredential`[``"resource"``]

#### Defined in

[src/ts/app/store.ts:15](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/app/store.ts#L15)

___

### VerifiableCredentialResource

Ƭ **VerifiableCredentialResource**: [`Resource`](API.md#resource) & { `type`: ``"VerifiableCredential"``  }

#### Defined in

[src/ts/app/store.ts:8](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/app/store.ts#L8)

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

[src/ts/wallet/wallet-builder.ts:4](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/wallet/wallet-builder.ts#L4)

___

### WalletOptions

Ƭ **WalletOptions**<`T`\>: [`WalletOptionsSettings`](interfaces/WalletOptionsSettings.md)<`T`\> & [`WalletOptionsCryptoWallet`](interfaces/WalletOptionsCryptoWallet.md)

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends [`BaseWalletModel`](interfaces/BaseWalletModel.md) |

#### Defined in

[src/ts/wallet/wallet-options.ts:16](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/wallet/wallet-options.ts#L16)

## Variables

### DEFAULT\_PROVIDER

• `Const` **DEFAULT\_PROVIDER**: ``"did:ethr:i3m"``

#### Defined in

[src/ts/veramo/veramo.ts:50](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/veramo/veramo.ts#L50)

___

### DEFAULT\_PROVIDERS\_DATA

• `Const` **DEFAULT\_PROVIDERS\_DATA**: `Record`<`string`, [`ProviderData`](interfaces/ProviderData.md)\>

#### Defined in

[src/ts/veramo/veramo.ts:51](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/veramo/veramo.ts#L51)

___

### base64url

• **base64url**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `decode` | (`str`: `string`) => `Buffer` |
| `encode` | (`buf`: `Buffer`) => `string` |

#### Defined in

[src/ts/utils/base64url.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/utils/base64url.ts#L9)

## Functions

### deriveKey

▸ **deriveKey**(`password`, `opts`, `returnBuffer?`): `Promise`<`KeyObject`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `password` | `BinaryLike` |
| `opts` | [`KdfOptions`](interfaces/KdfOptions.md) |
| `returnBuffer?` | ``false`` |

#### Returns

`Promise`<`KeyObject`\>

#### Defined in

[src/ts/impl/stores/file-store.ts:246](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/impl/stores/file-store.ts#L246)

▸ **deriveKey**(`password`, `opts`, `returnBuffer`): `Promise`<`Buffer`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `password` | `BinaryLike` |
| `opts` | [`KdfOptions`](interfaces/KdfOptions.md) |
| `returnBuffer` | ``true`` |

#### Returns

`Promise`<`Buffer`\>

#### Defined in

[src/ts/impl/stores/file-store.ts:247](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/impl/stores/file-store.ts#L247)

___

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

[src/ts/utils/did-jwt-verify.ts:45](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/utils/did-jwt-verify.ts#L45)

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

[src/ts/utils/credential-claims.ts:3](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/utils/credential-claims.ts#L3)

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

[src/ts/utils/generate-secret.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/utils/generate-secret.ts#L11)

___

### multipleExecutions

▸ **multipleExecutions**<`K`, `T`\>(`options`, `executors`, `fnName`, `...args`): `Promise`<[`MultipleExecutionsReturn`](API.md#multipleexecutionsreturn)<`K`, `T`\>[]\>

#### Type parameters

| Name | Type |
| :------ | :------ |
| `K` | extends `string` |
| `T` | extends `FunctionMap`<`K`\> |

#### Parameters

| Name | Type |
| :------ | :------ |
| `options` | [`MultipleExecutionsOptions`](interfaces/MultipleExecutionsOptions.md) |
| `executors` | `T`[] |
| `fnName` | `K` |
| `...args` | `any`[] |

#### Returns

`Promise`<[`MultipleExecutionsReturn`](API.md#multipleexecutionsreturn)<`K`, `T`\>[]\>

#### Defined in

[src/ts/utils/multiple-executions.ts:19](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/utils/multiple-executions.ts#L19)

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

[src/ts/utils/parseAddress.ts:7](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/utils/parseAddress.ts#L7)

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

[src/ts/utils/parseHex.ts:7](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/utils/parseHex.ts#L7)

___

### verifyDataSharingAgreementSignature

▸ **verifyDataSharingAgreementSignature**(`agreement`, `veramo`, `signer`): `Promise`<`Error`[]\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `agreement` | `DataSharingAgreement` |
| `veramo` | [`Veramo`](classes/Veramo.md)<[`BaseWalletModel`](interfaces/BaseWalletModel.md)\> |
| `signer` | ``"provider"`` \| ``"consumer"`` |

#### Returns

`Promise`<`Error`[]\>

#### Defined in

[src/ts/utils/data-sharing-agreement-validation.ts:6](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/utils/data-sharing-agreement-validation.ts#L6)
