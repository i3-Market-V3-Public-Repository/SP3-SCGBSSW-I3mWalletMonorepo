# Class: TestStore

## Implements

- [`Store`](../interfaces/Store.md)<[`BaseWalletModel`](../interfaces/BaseWalletModel.md)\>

## Table of contents

### Constructors

- [constructor](TestStore.md#constructor)

### Properties

- [model](TestStore.md#model)

### Methods

- [clear](TestStore.md#clear)
- [delete](TestStore.md#delete)
- [get](TestStore.md#get)
- [has](TestStore.md#has)
- [set](TestStore.md#set)

## Constructors

### constructor

• **new TestStore**()

#### Defined in

[base-wallet/src/ts/test/store.ts:8](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f6240c7/packages/base-wallet/src/ts/test/store.ts#L8)

## Properties

### model

• **model**: [`BaseWalletModel`](../interfaces/BaseWalletModel.md)

#### Defined in

[base-wallet/src/ts/test/store.ts:7](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f6240c7/packages/base-wallet/src/ts/test/store.ts#L7)

## Methods

### clear

▸ **clear**(): [`CanBePromise`](../API.md#canbepromise)<`void`\>

Delete all items.

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Implementation of

Store.clear

#### Defined in

[base-wallet/src/ts/test/store.ts:36](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f6240c7/packages/base-wallet/src/ts/test/store.ts#L36)

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

[base-wallet/src/ts/test/store.ts:32](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f6240c7/packages/base-wallet/src/ts/test/store.ts#L32)

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

[base-wallet/src/ts/test/store.ts:19](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f6240c7/packages/base-wallet/src/ts/test/store.ts#L19)

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

[base-wallet/src/ts/test/store.ts:28](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f6240c7/packages/base-wallet/src/ts/test/store.ts#L28)

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

[base-wallet/src/ts/test/store.ts:23](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f6240c7/packages/base-wallet/src/ts/test/store.ts#L23)
