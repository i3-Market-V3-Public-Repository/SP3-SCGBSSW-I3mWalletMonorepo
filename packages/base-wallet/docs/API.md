# @i3m/base-wallet - v1.4.0

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
- [Descriptors](API.md#descriptors)
- [DescriptorsMap](API.md#descriptorsmap)
- [DialogOptionContext](API.md#dialogoptioncontext)
- [DialogResponse](API.md#dialogresponse)
- [Identity](API.md#identity)
- [KeyLike](API.md#keylike)
- [ProviderData](API.md#providerdata)
- [Resource](API.md#resource)
- [ToastType](API.md#toasttype)
- [TypedArray](API.md#typedarray)
- [WalletBuilder](API.md#walletbuilder)
- [WalletOptions](API.md#walletoptions)

### Variables

- [base64url](API.md#base64url)

### Functions

- [getCredentialClaims](API.md#getcredentialclaims)
- [jwkSecret](API.md#jwksecret)

## Type Aliases

### CanBePromise

Ƭ **CanBePromise**<`T`\>: `Promise`<`T`\> \| `T`

#### Type parameters

| Name |
| :------ |
| `T` |

#### Defined in

[src/ts/utils/types.ts:1](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/src/ts/utils/types.ts#L1)

___

### Descriptors

Ƭ **Descriptors**<`T`\>: `TextFormDescriptor` \| `ConfirmationFormDescriptor` \| `SelectFormDescriptor`<`T`\>

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | `any` |

#### Defined in

[src/ts/app/dialog.ts:42](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/src/ts/app/dialog.ts#L42)

___

### DescriptorsMap

Ƭ **DescriptorsMap**<`T`\>: { [K in keyof Partial<T\>]: Descriptors<T[K]\> }

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | `any` |

#### Defined in

[src/ts/app/dialog.ts:43](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/src/ts/app/dialog.ts#L43)

___

### DialogOptionContext

Ƭ **DialogOptionContext**: ``"success"`` \| ``"danger"``

#### Defined in

[src/ts/app/dialog.ts:40](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/src/ts/app/dialog.ts#L40)

___

### DialogResponse

Ƭ **DialogResponse**<`T`\>: `Promise`<`T` \| `undefined`\>

#### Type parameters

| Name |
| :------ |
| `T` |

#### Defined in

[src/ts/app/dialog.ts:52](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/src/ts/app/dialog.ts#L52)

___

### Identity

Ƭ **Identity**: `IIdentifier`

#### Defined in

[src/ts/app/store.ts:6](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/src/ts/app/store.ts#L6)

___

### KeyLike

Ƭ **KeyLike**: `Uint8Array`

#### Defined in

[src/ts/utils/types.ts:5](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/src/ts/utils/types.ts#L5)

___

### ProviderData

Ƭ **ProviderData**: `Omit`<`ConstructorParameters`<typeof `EthrDIDProvider`\>[``0``], ``"defaultKms"``\>

#### Defined in

[src/ts/veramo/veramo.ts:43](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/src/ts/veramo/veramo.ts#L43)

___

### Resource

Ƭ **Resource**: `WalletComponents.Schemas.Resource` & `WalletComponents.Schemas.ResourceId`

#### Defined in

[src/ts/app/store.ts:5](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/src/ts/app/store.ts#L5)

___

### ToastType

Ƭ **ToastType**: ``"info"`` \| ``"success"`` \| ``"warning"`` \| ``"error"``

#### Defined in

[src/ts/app/toast.ts:2](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/src/ts/app/toast.ts#L2)

___

### TypedArray

Ƭ **TypedArray**: `Int8Array` \| `Uint8Array` \| `Uint8ClampedArray` \| `Int16Array` \| `Uint16Array` \| `Int32Array` \| `Uint32Array` \| `Float32Array` \| `Float64Array` \| `BigInt64Array` \| `BigUint64Array`

#### Defined in

[src/ts/utils/types.ts:3](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/src/ts/utils/types.ts#L3)

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

[src/ts/wallet/wallet-builder.ts:4](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/src/ts/wallet/wallet-builder.ts#L4)

___

### WalletOptions

Ƭ **WalletOptions**<`T`\>: [`WalletOptionsSettings`](interfaces/WalletOptionsSettings.md)<`T`\> & [`WalletOptionsCryptoWallet`](interfaces/WalletOptionsCryptoWallet.md)

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends [`BaseWalletModel`](interfaces/BaseWalletModel.md) |

#### Defined in

[src/ts/wallet/wallet-options.ts:16](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/src/ts/wallet/wallet-options.ts#L16)

## Variables

### base64url

• **base64url**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `decode` | (`str`: `string`) => `Buffer` |
| `encode` | (`buf`: `Buffer`) => `string` |

#### Defined in

[src/ts/utils/base64url.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/src/ts/utils/base64url.ts#L9)

## Functions

### getCredentialClaims

▸ **getCredentialClaims**(`vc`): `string`[]

#### Parameters

| Name | Type |
| :------ | :------ |
| `vc` | `VerifiableCredential` |

#### Returns

`string`[]

#### Defined in

[src/ts/utils/credential-claims.ts:3](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/src/ts/utils/credential-claims.ts#L3)

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

[src/ts/utils/generate-secret.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/src/ts/utils/generate-secret.ts#L11)
