# Class: RamStore

A class that implements a storage in RAM to be used by a wallet

## Implements

- [`Store`](../interfaces/Store.md)<[`BaseWalletModel`](../interfaces/BaseWalletModel.md)\>

## Table of contents

### Constructors

- [constructor](RamStore.md#constructor)

### Properties

- [model](RamStore.md#model)

### Methods

- [clear](RamStore.md#clear)
- [delete](RamStore.md#delete)
- [get](RamStore.md#get)
- [has](RamStore.md#has)
- [set](RamStore.md#set)

## Constructors

### constructor

• **new RamStore**()

#### Defined in

[base-wallet/src/ts/impl/stores/ram-store.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8582996/packages/base-wallet/src/ts/impl/stores/ram-store.ts#L11)

## Properties

### model

• **model**: [`BaseWalletModel`](../interfaces/BaseWalletModel.md)

#### Defined in

[base-wallet/src/ts/impl/stores/ram-store.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8582996/packages/base-wallet/src/ts/impl/stores/ram-store.ts#L10)

## Methods

### clear

▸ **clear**(): [`CanBePromise`](../API.md#canbepromise)<`void`\>

Delete all items.

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Implementation of

Store.clear

#### Defined in

[base-wallet/src/ts/impl/stores/ram-store.ts:39](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8582996/packages/base-wallet/src/ts/impl/stores/ram-store.ts#L39)

___

### delete

▸ **delete**<`Key`\>(`key`): [`CanBePromise`](../API.md#canbepromise)<`void`\>

Delete an item.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Key` | extends ``"accounts"`` |

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `key` | `Key` | The key of the item to delete. |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Implementation of

[Store](../interfaces/Store.md).[delete](../interfaces/Store.md#delete)

#### Defined in

[base-wallet/src/ts/impl/stores/ram-store.ts:35](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8582996/packages/base-wallet/src/ts/impl/stores/ram-store.ts#L35)

___

### get

▸ **get**(`key`, `defaultValue?`): `any`

Get an item.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `key` | `any` | The key of the item to get. |
| `defaultValue?` | `any` | - |

#### Returns

`any`

#### Implementation of

[Store](../interfaces/Store.md).[get](../interfaces/Store.md#get)

#### Defined in

[base-wallet/src/ts/impl/stores/ram-store.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8582996/packages/base-wallet/src/ts/impl/stores/ram-store.ts#L22)

___

### has

▸ **has**<`Key`\>(`key`): [`CanBePromise`](../API.md#canbepromise)<`boolean`\>

Check if an item exists.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Key` | extends ``"accounts"`` |

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `key` | `Key` | The key of the item to check. |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`boolean`\>

#### Implementation of

[Store](../interfaces/Store.md).[has](../interfaces/Store.md#has)

#### Defined in

[base-wallet/src/ts/impl/stores/ram-store.ts:31](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8582996/packages/base-wallet/src/ts/impl/stores/ram-store.ts#L31)

___

### set

▸ **set**(`key`, `value`): [`CanBePromise`](../API.md#canbepromise)<`void`\>

Set an item.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `key` | `string` | The key of the item to set |
| `value` | `unknown` | The value to set |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Implementation of

[Store](../interfaces/Store.md).[set](../interfaces/Store.md#set)

#### Defined in

[base-wallet/src/ts/impl/stores/ram-store.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8582996/packages/base-wallet/src/ts/impl/stores/ram-store.ts#L26)
