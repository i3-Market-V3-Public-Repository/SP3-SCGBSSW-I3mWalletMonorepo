# Class: Veramo<T\>

## Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends [`BaseWalletModel`](../interfaces/BaseWalletModel.md) = [`BaseWalletModel`](../interfaces/BaseWalletModel.md) |

## Table of contents

### Constructors

- [constructor](Veramo.md#constructor)

### Properties

- [agent](Veramo.md#agent)
- [defaultKms](Veramo.md#defaultkms)
- [providers](Veramo.md#providers)
- [providersData](Veramo.md#providersdata)

### Methods

- [getProvider](Veramo.md#getprovider)

## Constructors

### constructor

• **new Veramo**<`T`\>(`store`, `keyWallet`, `providersData`)

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends [`BaseWalletModel`](../interfaces/BaseWalletModel.md) = [`BaseWalletModel`](../interfaces/BaseWalletModel.md) |

#### Parameters

| Name | Type |
| :------ | :------ |
| `store` | [`Store`](../interfaces/Store.md)<`T`\> |
| `keyWallet` | [`KeyWallet`](../interfaces/KeyWallet.md)<`Uint8Array`\> |
| `providersData` | `Record`<`string`, [`ProviderData`](../API.md#providerdata)\> |

#### Defined in

src/ts/veramo/veramo.ts:67

## Properties

### agent

• **agent**: `TAgent`<`PluginMap`\>

#### Defined in

src/ts/veramo/veramo.ts:62

___

### defaultKms

• **defaultKms**: `string` = `'keyWallet'`

#### Defined in

src/ts/veramo/veramo.ts:64

___

### providers

• **providers**: `Record`<`string`, `AbstractIdentifierProvider`\>

#### Defined in

src/ts/veramo/veramo.ts:63

___

### providersData

• **providersData**: `Record`<`string`, [`ProviderData`](../API.md#providerdata)\>

#### Defined in

src/ts/veramo/veramo.ts:65

## Methods

### getProvider

▸ **getProvider**(`name`): `AbstractIdentifierProvider`

#### Parameters

| Name | Type |
| :------ | :------ |
| `name` | `string` |

#### Returns

`AbstractIdentifierProvider`

#### Defined in

src/ts/veramo/veramo.ts:122
