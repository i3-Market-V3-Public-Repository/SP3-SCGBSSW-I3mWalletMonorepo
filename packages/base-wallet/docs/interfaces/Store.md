# Interface: Store<T\>

## Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends `Record`<`string`, `any`\> = `Record`<`string`, `unknown`\> |

## Implemented by

- [`FileStore`](../classes/FileStore.md)
- [`TestStore`](../classes/TestStore.md)

## Table of contents

### Properties

- [clear](Store.md#clear)
- [getPath](Store.md#getpath)
- [getStore](Store.md#getstore)

### Methods

- [delete](Store.md#delete)
- [get](Store.md#get)
- [has](Store.md#has)
- [set](Store.md#set)

## Properties

### clear

• **clear**: () => [`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Type declaration

▸ (): [`CanBePromise`](../API.md#canbepromise)<`void`\>

Delete all items.

##### Returns

[`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Defined in

[src/ts/app/store.ts:69](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/base-wallet/src/ts/app/store.ts#L69)

___

### getPath

• **getPath**: () => `string`

#### Type declaration

▸ (): `string`

Get the path of the store

##### Returns

`string`

The store path

#### Defined in

[src/ts/app/store.ts:81](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/base-wallet/src/ts/app/store.ts#L81)

___

### getStore

• **getStore**: () => [`CanBePromise`](../API.md#canbepromise)<`T`\>

#### Type declaration

▸ (): [`CanBePromise`](../API.md#canbepromise)<`T`\>

Return a readonly version of the complete store

##### Returns

[`CanBePromise`](../API.md#canbepromise)<`T`\>

The entire store

#### Defined in

[src/ts/app/store.ts:75](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/base-wallet/src/ts/app/store.ts#L75)

## Methods

### delete

▸ **delete**<`Key`\>(`key`): [`CanBePromise`](../API.md#canbepromise)<`void`\>

Delete an item.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Key` | extends `string` \| `number` \| `symbol` |

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `key` | `Key` | The key of the item to delete. |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Defined in

[src/ts/app/store.ts:63](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/base-wallet/src/ts/app/store.ts#L63)

▸ **delete**(`key`): [`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `key` | `string` |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Defined in

[src/ts/app/store.ts:64](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/base-wallet/src/ts/app/store.ts#L64)

___

### get

▸ **get**<`Key`\>(`key`): [`CanBePromise`](../API.md#canbepromise)<`T`[`Key`]\>

Get an item.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Key` | extends `string` \| `number` \| `symbol` |

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `key` | `Key` | The key of the item to get. |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`T`[`Key`]\>

#### Defined in

[src/ts/app/store.ts:35](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/base-wallet/src/ts/app/store.ts#L35)

▸ **get**<`Key`\>(`key`, `defaultValue`): [`CanBePromise`](../API.md#canbepromise)<`Required`<`T`\>[`Key`]\>

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Key` | extends `string` \| `number` \| `symbol` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `key` | `Key` |
| `defaultValue` | `Required`<`T`\>[`Key`] |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`Required`<`T`\>[`Key`]\>

#### Defined in

[src/ts/app/store.ts:36](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/base-wallet/src/ts/app/store.ts#L36)

___

### has

▸ **has**<`Key`\>(`key`): [`CanBePromise`](../API.md#canbepromise)<`boolean`\>

Check if an item exists.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Key` | extends `string` \| `number` \| `symbol` |

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `key` | `Key` | The key of the item to check. |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`boolean`\>

#### Defined in

[src/ts/app/store.ts:56](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/base-wallet/src/ts/app/store.ts#L56)

▸ **has**(`key`): [`CanBePromise`](../API.md#canbepromise)<`boolean`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `key` | `string` |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`boolean`\>

#### Defined in

[src/ts/app/store.ts:57](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/base-wallet/src/ts/app/store.ts#L57)

___

### set

▸ **set**(`store`): [`CanBePromise`](../API.md#canbepromise)<`void`\>

Set multiple keys at once.

#### Parameters

| Name | Type |
| :------ | :------ |
| `store` | `Partial`<`T`\> |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Defined in

[src/ts/app/store.ts:42](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/base-wallet/src/ts/app/store.ts#L42)

▸ **set**<`Key`\>(`key`, `value`): [`CanBePromise`](../API.md#canbepromise)<`void`\>

Set an item.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Key` | extends `string` \| `number` \| `symbol` |

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `key` | `Key` | The key of the item to set |
| `value` | `T`[`Key`] | The value to set |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Defined in

[src/ts/app/store.ts:48](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/base-wallet/src/ts/app/store.ts#L48)

▸ **set**(`key`, `value`): [`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `key` | `string` |
| `value` | `unknown` |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Defined in

[src/ts/app/store.ts:49](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/base-wallet/src/ts/app/store.ts#L49)
