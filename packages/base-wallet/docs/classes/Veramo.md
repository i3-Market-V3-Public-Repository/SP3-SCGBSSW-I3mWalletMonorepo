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
| `providersData` | `Record`<`string`, [`ProviderData`](../interfaces/ProviderData.md)\> |

#### Defined in

[src/ts/veramo/veramo.ts:69](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/veramo/veramo.ts#L69)

## Properties

### agent

• **agent**: `TAgent`<`PluginMap`\>

#### Defined in

[src/ts/veramo/veramo.ts:64](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/veramo/veramo.ts#L64)

___

### defaultKms

• **defaultKms**: `string` = `'keyWallet'`

#### Defined in

[src/ts/veramo/veramo.ts:66](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/veramo/veramo.ts#L66)

___

### providers

• **providers**: `Record`<`string`, `AbstractIdentifierProvider`\>

#### Defined in

[src/ts/veramo/veramo.ts:65](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/veramo/veramo.ts#L65)

___

### providersData

• **providersData**: `Record`<`string`, [`ProviderData`](../interfaces/ProviderData.md)\>

#### Defined in

[src/ts/veramo/veramo.ts:67](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/veramo/veramo.ts#L67)

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

[src/ts/veramo/veramo.ts:127](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c0d10db/packages/base-wallet/src/ts/veramo/veramo.ts#L127)
