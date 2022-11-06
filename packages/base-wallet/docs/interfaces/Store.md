# Interface: Store<T\>

## Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends [`BaseWalletModel`](BaseWalletModel.md) |

## Implemented by

- [`FileStore`](../classes/FileStore.md)
- [`RamStore`](../classes/RamStore.md)
- [`TestStore`](../classes/TestStore.md)

## Table of contents

### Properties

- [clear](Store.md#clear)

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

[base-wallet/src/ts/app/store.ts:62](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b0d0c21/packages/base-wallet/src/ts/app/store.ts#L62)

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

[base-wallet/src/ts/app/store.ts:56](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b0d0c21/packages/base-wallet/src/ts/app/store.ts#L56)

▸ **delete**(`key`): [`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `key` | `string` |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Defined in

[base-wallet/src/ts/app/store.ts:57](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b0d0c21/packages/base-wallet/src/ts/app/store.ts#L57)

___

### get

▸ **get**<`Key`\>(`key`): [`CanBePromise`](../API.md#canbepromise)<`Partial`<`T`\>[`Key`]\>

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

[`CanBePromise`](../API.md#canbepromise)<`Partial`<`T`\>[`Key`]\>

#### Defined in

[base-wallet/src/ts/app/store.ts:33](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b0d0c21/packages/base-wallet/src/ts/app/store.ts#L33)

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

[base-wallet/src/ts/app/store.ts:34](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b0d0c21/packages/base-wallet/src/ts/app/store.ts#L34)

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

[base-wallet/src/ts/app/store.ts:49](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b0d0c21/packages/base-wallet/src/ts/app/store.ts#L49)

▸ **has**(`key`): [`CanBePromise`](../API.md#canbepromise)<`boolean`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `key` | `string` |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`boolean`\>

#### Defined in

[base-wallet/src/ts/app/store.ts:50](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b0d0c21/packages/base-wallet/src/ts/app/store.ts#L50)

___

### set

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

[base-wallet/src/ts/app/store.ts:41](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b0d0c21/packages/base-wallet/src/ts/app/store.ts#L41)

▸ **set**(`key`, `value`): [`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `key` | `string` |
| `value` | `unknown` |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Defined in

[base-wallet/src/ts/app/store.ts:42](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b0d0c21/packages/base-wallet/src/ts/app/store.ts#L42)
