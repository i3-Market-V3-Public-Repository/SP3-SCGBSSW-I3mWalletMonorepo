# Class: FileStore

A class that implements a storage for the wallet in a single file. The server wallet uses a file as storage.

`filepath` is the path to the Wallet's storage file. If you are using a container it should be a path to a file that persists (like one in a volume)

The wallet's storage-file can be encrypted for added security by passing an optional `password`.

## Implements

- [`Store`](../interfaces/Store.md)<[`BaseWalletModel`](../interfaces/BaseWalletModel.md)\>

## Table of contents

### Constructors

- [constructor](FileStore.md#constructor)

### Properties

- [filepath](FileStore.md#filepath)
- [password](FileStore.md#password)

### Methods

- [clear](FileStore.md#clear)
- [delete](FileStore.md#delete)
- [get](FileStore.md#get)
- [has](FileStore.md#has)
- [set](FileStore.md#set)

## Constructors

### constructor

• **new FileStore**(`filepath`, `password?`)

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `filepath` | `string` | an absolute path to the file that will be used to store wallet data |
| `password?` | `string` | if provided a key will be derived from the password and the store file will be encrypted |

#### Defined in

[base-wallet/src/ts/impl/stores/file-store.ts:23](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/base-wallet/src/ts/impl/stores/file-store.ts#L23)

## Properties

### filepath

• **filepath**: `string`

#### Defined in

[base-wallet/src/ts/impl/stores/file-store.ts:15](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/base-wallet/src/ts/impl/stores/file-store.ts#L15)

___

### password

• `Optional` **password**: `string`

#### Defined in

[base-wallet/src/ts/impl/stores/file-store.ts:16](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/base-wallet/src/ts/impl/stores/file-store.ts#L16)

## Methods

### clear

▸ **clear**(): `Promise`<`void`\>

Delete all items.

#### Returns

`Promise`<`void`\>

#### Implementation of

Store.clear

#### Defined in

[base-wallet/src/ts/impl/stores/file-store.ts:152](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/base-wallet/src/ts/impl/stores/file-store.ts#L152)

___

### delete

▸ **delete**<`Key`\>(`key`): `Promise`<`void`\>

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

`Promise`<`void`\>

#### Implementation of

[Store](../interfaces/Store.md).[delete](../interfaces/Store.md#delete)

#### Defined in

[base-wallet/src/ts/impl/stores/file-store.ts:145](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/base-wallet/src/ts/impl/stores/file-store.ts#L145)

___

### get

▸ **get**(`key`, `defaultValue?`): `Promise`<`any`\>

Get an item.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `key` | `any` | The key of the item to get. |
| `defaultValue?` | `any` | - |

#### Returns

`Promise`<`any`\>

#### Implementation of

[Store](../interfaces/Store.md).[get](../interfaces/Store.md#get)

#### Defined in

[base-wallet/src/ts/impl/stores/file-store.ts:125](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/base-wallet/src/ts/impl/stores/file-store.ts#L125)

___

### has

▸ **has**<`Key`\>(`key`): `Promise`<`boolean`\>

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

`Promise`<`boolean`\>

#### Implementation of

[Store](../interfaces/Store.md).[has](../interfaces/Store.md#has)

#### Defined in

[base-wallet/src/ts/impl/stores/file-store.ts:139](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/base-wallet/src/ts/impl/stores/file-store.ts#L139)

___

### set

▸ **set**(`key`, `value`): `Promise`<`void`\>

Set an item.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `key` | `string` | The key of the item to set |
| `value` | `unknown` | The value to set |

#### Returns

`Promise`<`void`\>

#### Implementation of

[Store](../interfaces/Store.md).[set](../interfaces/Store.md#set)

#### Defined in

[base-wallet/src/ts/impl/stores/file-store.ts:131](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/base-wallet/src/ts/impl/stores/file-store.ts#L131)
