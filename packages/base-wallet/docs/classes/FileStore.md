# Class: FileStore<T\>

A class that implements a storage for the wallet in a single file. The server wallet uses a file as storage.

`filepath` is the path to the Wallet's storage file. If you are using a container it should be a path to a file that persists (like one in a volume)

The wallet's storage-file can be encrypted for added security.

## Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends `Record`<`string`, `any`\> = `Record`<`string`, `unknown`\> |

## Implements

- [`Store`](../interfaces/Store.md)<`T`\>

## Table of contents

### Constructors

- [constructor](FileStore.md#constructor)

### Properties

- [defaultModel](FileStore.md#defaultmodel)
- [filepath](FileStore.md#filepath)
- [initialized](FileStore.md#initialized)

### Methods

- [clear](FileStore.md#clear)
- [delete](FileStore.md#delete)
- [deriveKey](FileStore.md#derivekey)
- [get](FileStore.md#get)
- [getPath](FileStore.md#getpath)
- [getStore](FileStore.md#getstore)
- [has](FileStore.md#has)
- [set](FileStore.md#set)

## Constructors

### constructor

• **new FileStore**<`T`\>(`filepath`, `keyObject?`, `defaultModel?`)

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends `Record`<`string`, `any`\> = `Record`<`string`, `unknown`\> |

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `filepath` | `string` | an absolute path to the file that will be used to store wallet data |
| `keyObject?` | `KeyObject` | a key object holding a 32 bytes symmetric key to use for encryption/decryption of the storage |
| `defaultModel?` | `T` | - |

#### Defined in

[src/ts/impl/stores/file-store.ts:27](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9fada86/packages/base-wallet/src/ts/impl/stores/file-store.ts#L27)

• **new FileStore**<`T`\>(`filepath`, `password?`, `defaultModel?`)

**`Deprecated`**

you should consider passing a more secure KeyObject derived from your password

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends `Record`<`string`, `any`\> = `Record`<`string`, `unknown`\> |

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `filepath` | `string` | an absolute path to the file that will be used to store wallet data |
| `password?` | `string` | if provided a key will be derived from the password and the store file will be encrypted |
| `defaultModel?` | `T` | - |

#### Defined in

[src/ts/impl/stores/file-store.ts:35](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9fada86/packages/base-wallet/src/ts/impl/stores/file-store.ts#L35)

## Properties

### defaultModel

• **defaultModel**: `T`

#### Defined in

[src/ts/impl/stores/file-store.ts:20](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9fada86/packages/base-wallet/src/ts/impl/stores/file-store.ts#L20)

___

### filepath

• **filepath**: `string`

#### Defined in

[src/ts/impl/stores/file-store.ts:15](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9fada86/packages/base-wallet/src/ts/impl/stores/file-store.ts#L15)

___

### initialized

• **initialized**: `Promise`<`void`\>

#### Defined in

[src/ts/impl/stores/file-store.ts:19](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9fada86/packages/base-wallet/src/ts/impl/stores/file-store.ts#L19)

## Methods

### clear

▸ **clear**(): `Promise`<`void`\>

Delete all items.

#### Returns

`Promise`<`void`\>

#### Implementation of

Store.clear

#### Defined in

[src/ts/impl/stores/file-store.ts:186](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9fada86/packages/base-wallet/src/ts/impl/stores/file-store.ts#L186)

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

[src/ts/impl/stores/file-store.ts:178](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9fada86/packages/base-wallet/src/ts/impl/stores/file-store.ts#L178)

___

### deriveKey

▸ **deriveKey**(`password`, `salt?`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `password` | `string` |
| `salt?` | `Buffer` |

#### Returns

`Promise`<`void`\>

#### Defined in

[src/ts/impl/stores/file-store.ts:63](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9fada86/packages/base-wallet/src/ts/impl/stores/file-store.ts#L63)

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

[src/ts/impl/stores/file-store.ts:151](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9fada86/packages/base-wallet/src/ts/impl/stores/file-store.ts#L151)

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

[src/ts/impl/stores/file-store.ts:198](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9fada86/packages/base-wallet/src/ts/impl/stores/file-store.ts#L198)

___

### getStore

▸ **getStore**(): `Promise`<`T`\>

Return a readonly version of the complete store

#### Returns

`Promise`<`T`\>

The entire store

#### Implementation of

Store.getStore

#### Defined in

[src/ts/impl/stores/file-store.ts:192](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9fada86/packages/base-wallet/src/ts/impl/stores/file-store.ts#L192)

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

[src/ts/impl/stores/file-store.ts:171](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9fada86/packages/base-wallet/src/ts/impl/stores/file-store.ts#L171)

___

### set

▸ **set**(`keyOrStore`, `value?`): `Promise`<`void`\>

Set multiple keys at once.

#### Parameters

| Name | Type |
| :------ | :------ |
| `keyOrStore` | `any` |
| `value?` | `any` |

#### Returns

`Promise`<`void`\>

#### Implementation of

[Store](../interfaces/Store.md).[set](../interfaces/Store.md#set)

#### Defined in

[src/ts/impl/stores/file-store.ts:158](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9fada86/packages/base-wallet/src/ts/impl/stores/file-store.ts#L158)
