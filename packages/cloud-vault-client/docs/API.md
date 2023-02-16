# @i3m/cloud-vault-client - v2.5.7

A TypeScript/JavaScript implementation of a client for the i3M-Wallet Cloud-Vault server

## Table of contents

### Classes

- [KeyManager](classes/KeyManager.md)
- [SecretKey](classes/SecretKey.md)
- [VaultClient](classes/VaultClient.md)
- [VaultError](classes/VaultError.md)

### Interfaces

- [KeyDerivationOptions](interfaces/KeyDerivationOptions.md)
- [ScryptOptions](interfaces/ScryptOptions.md)
- [VaultStorage](interfaces/VaultStorage.md)

### Type Aliases

- [DataForError](API.md#dataforerror)
- [VaultErrorData](API.md#vaulterrordata)
- [VaultErrorName](API.md#vaulterrorname)

### Functions

- [checkErrorType](API.md#checkerrortype)
- [deriveKey](API.md#derivekey)

## Type Aliases

### DataForError

Ƭ **DataForError**<`T`\>: [`VaultErrorData`](API.md#vaulterrordata)[`T`]

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends [`VaultErrorName`](API.md#vaulterrorname) |

#### Defined in

[cloud-vault-client/src/ts/error.ts:35](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/5ef8685/packages/cloud-vault-client/src/ts/error.ts#L35)

___

### VaultErrorData

Ƭ **VaultErrorData**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `conflict` | { `localTimestamp?`: `number` ; `remoteTimestamp?`: `number`  } |
| `conflict.localTimestamp?` | `number` |
| `conflict.remoteTimestamp?` | `number` |
| `error` | `any` |
| `http-connection-error` | { `request`: { `data?`: `any` ; `headers?`: { `[header: string]`: `string`;  } ; `method?`: `string` ; `url?`: `string`  } ; `response?`: { `data?`: `any` ; `headers?`: { `[header: string]`: `string`;  } ; `status?`: `number`  }  } |
| `http-connection-error.request` | { `data?`: `any` ; `headers?`: { `[header: string]`: `string`;  } ; `method?`: `string` ; `url?`: `string`  } |
| `http-connection-error.request.data?` | `any` |
| `http-connection-error.request.headers?` | { `[header: string]`: `string`;  } |
| `http-connection-error.request.method?` | `string` |
| `http-connection-error.request.url?` | `string` |
| `http-connection-error.response?` | { `data?`: `any` ; `headers?`: { `[header: string]`: `string`;  } ; `status?`: `number`  } |
| `http-connection-error.response.data?` | `any` |
| `http-connection-error.response.headers?` | { `[header: string]`: `string`;  } |
| `http-connection-error.response.status?` | `number` |
| `invalid-credentials` | `any` |
| `no-uploaded-storage` | `any` |
| `not-initialized` | `any` |
| `sse-connection-error` | `Event` |
| `unauthorized` | `any` |
| `unknown` | `any` |
| `validation` | { `data?`: `any` ; `description?`: `string`  } |
| `validation.data?` | `any` |
| `validation.description?` | `string` |

#### Defined in

[cloud-vault-client/src/ts/error.ts:4](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/5ef8685/packages/cloud-vault-client/src/ts/error.ts#L4)

___

### VaultErrorName

Ƭ **VaultErrorName**: keyof [`VaultErrorData`](API.md#vaulterrordata)

#### Defined in

[cloud-vault-client/src/ts/error.ts:34](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/5ef8685/packages/cloud-vault-client/src/ts/error.ts#L34)

## Functions

### checkErrorType

▸ **checkErrorType**<`T`\>(`err`, `type`): err is VaultError<T\>

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends keyof [`VaultErrorData`](API.md#vaulterrordata) |

#### Parameters

| Name | Type |
| :------ | :------ |
| `err` | [`VaultError`](classes/VaultError.md)<keyof [`VaultErrorData`](API.md#vaulterrordata)\> |
| `type` | `T` |

#### Returns

err is VaultError<T\>

#### Defined in

[cloud-vault-client/src/ts/error.ts:88](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/5ef8685/packages/cloud-vault-client/src/ts/error.ts#L88)

___

### deriveKey

▸ **deriveKey**(`password`, `opts`): `Promise`<`KeyObject`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `password` | `string` |
| `opts` | [`KeyDerivationOptions`](interfaces/KeyDerivationOptions.md) |

#### Returns

`Promise`<`KeyObject`\>

#### Defined in

[cloud-vault-client/src/ts/key-manager.ts:74](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/5ef8685/packages/cloud-vault-client/src/ts/key-manager.ts#L74)

▸ **deriveKey**(`key`, `opts`): `Promise`<`KeyObject`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `key` | `KeyObject` |
| `opts` | [`KeyDerivationOptions`](interfaces/KeyDerivationOptions.md) |

#### Returns

`Promise`<`KeyObject`\>

#### Defined in

[cloud-vault-client/src/ts/key-manager.ts:75](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/5ef8685/packages/cloud-vault-client/src/ts/key-manager.ts#L75)
