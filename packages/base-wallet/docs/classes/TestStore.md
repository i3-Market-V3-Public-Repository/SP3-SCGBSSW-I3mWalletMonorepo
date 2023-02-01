# Class: TestStore<T\>

A class that implements a storage in RAM to be used by a wallet

## Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends `Record`<`string`, `any`\> = `Record`<`string`, `unknown`\> |

## Implements

- [`Store`](../interfaces/Store.md)<`T`\>

## Table of contents

### Constructors

- [constructor](TestStore.md#constructor)

### Properties

- [defaultModel](TestStore.md#defaultmodel)
- [model](TestStore.md#model)

### Methods

- [clear](TestStore.md#clear)
- [delete](TestStore.md#delete)
- [get](TestStore.md#get)
- [getPath](TestStore.md#getpath)
- [getStore](TestStore.md#getstore)
- [has](TestStore.md#has)
- [set](TestStore.md#set)

## Constructors

### constructor

• **new TestStore**<`T`\>(`defaultModel`)

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends `Record`<`string`, `any`\> = `Record`<`string`, `unknown`\> |

#### Parameters

| Name | Type |
| :------ | :------ |
| `defaultModel` | `T` |

#### Defined in

[src/ts/impl/stores/ram-store.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/base-wallet/src/ts/impl/stores/ram-store.ts#L11)

## Properties

### defaultModel

• `Protected` **defaultModel**: `T`

#### Defined in

[src/ts/impl/stores/ram-store.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/base-wallet/src/ts/impl/stores/ram-store.ts#L11)

___

### model

• **model**: `T`

#### Defined in

[src/ts/impl/stores/ram-store.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/base-wallet/src/ts/impl/stores/ram-store.ts#L10)

## Methods

### clear

▸ **clear**(): [`CanBePromise`](../API.md#canbepromise)<`void`\>

Delete all items.

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Implementation of

Store.clear

#### Defined in

[src/ts/impl/stores/ram-store.ts:35](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/base-wallet/src/ts/impl/stores/ram-store.ts#L35)

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

[src/ts/impl/stores/ram-store.ts:31](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/base-wallet/src/ts/impl/stores/ram-store.ts#L31)

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

[src/ts/impl/stores/ram-store.ts:15](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/base-wallet/src/ts/impl/stores/ram-store.ts#L15)

___

### getPath

▸ **getPath**(): `string`

Get the path of the store

#### Returns

`string`

The store path

#### Implementation of

Store.getPath

#### Defined in

[src/ts/impl/stores/ram-store.ts:43](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/base-wallet/src/ts/impl/stores/ram-store.ts#L43)

___

### getStore

▸ **getStore**(): [`CanBePromise`](../API.md#canbepromise)<`T`\>

Return a readonly version of the complete store

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`T`\>

The entire store

#### Implementation of

Store.getStore

#### Defined in

[src/ts/impl/stores/ram-store.ts:39](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/base-wallet/src/ts/impl/stores/ram-store.ts#L39)

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

[src/ts/impl/stores/ram-store.ts:27](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/base-wallet/src/ts/impl/stores/ram-store.ts#L27)

___

### set

▸ **set**(`keyOrStore?`, `value?`): [`CanBePromise`](../API.md#canbepromise)<`void`\>

Set multiple keys at once.

#### Parameters

| Name | Type |
| :------ | :------ |
| `keyOrStore?` | `any` |
| `value?` | `any` |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Implementation of

[Store](../interfaces/Store.md).[set](../interfaces/Store.md#set)

#### Defined in

[src/ts/impl/stores/ram-store.ts:19](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/base-wallet/src/ts/impl/stores/ram-store.ts#L19)
