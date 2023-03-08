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

- [CbOnEventFn](API.md#cboneventfn)
- [DataForError](API.md#dataforerror)
- [VaultErrorData](API.md#vaulterrordata)
- [VaultErrorName](API.md#vaulterrorname)
- [VaultState](API.md#vaultstate)

### Variables

- [VAULT\_STATE](API.md#vault_state)

### Functions

- [checkErrorType](API.md#checkerrortype)
- [deriveKey](API.md#derivekey)

## Type Aliases

### CbOnEventFn

Ƭ **CbOnEventFn**<`T`\>: (...`args`: `ArgsForEvent`<`T`\>) => `void`

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends `VaultEventName` |

#### Type declaration

▸ (`...args`): `void`

##### Parameters

| Name | Type |
| :------ | :------ |
| `...args` | `ArgsForEvent`<`T`\> |

##### Returns

`void`

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:14](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/cloud-vault-client/src/ts/vault-client.ts#L14)

___

### DataForError

Ƭ **DataForError**<`T`\>: [`VaultErrorData`](API.md#vaulterrordata)[`T`]

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends [`VaultErrorName`](API.md#vaulterrorname) |

#### Defined in

[cloud-vault-client/src/ts/error.ts:37](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/cloud-vault-client/src/ts/error.ts#L37)

___

### VaultErrorData

Ƭ **VaultErrorData**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `conflict` | { `localTimestamp?`: `number` ; `remoteTimestamp?`: `number`  } |
| `conflict.localTimestamp?` | `number` |
| `conflict.remoteTimestamp?` | `number` |
| `error` | `Error` |
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
| `quota-exceeded` | `string` |
| `sse-connection-error` | `any` |
| `unauthorized` | `any` |
| `unknown` | `any` |
| `validation` | { `data?`: `any` ; `description?`: `string`  } |
| `validation.data?` | `any` |
| `validation.description?` | `string` |

#### Defined in

[cloud-vault-client/src/ts/error.ts:5](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/cloud-vault-client/src/ts/error.ts#L5)

___

### VaultErrorName

Ƭ **VaultErrorName**: keyof [`VaultErrorData`](API.md#vaulterrordata)

#### Defined in

[cloud-vault-client/src/ts/error.ts:36](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/cloud-vault-client/src/ts/error.ts#L36)

___

### VaultState

Ƭ **VaultState**: typeof [`VAULT_STATE`](API.md#vault_state)[``"NOT_INITIALIZED"``] \| typeof [`VAULT_STATE`](API.md#vault_state)[``"INITIALIZED"``] \| typeof [`VAULT_STATE`](API.md#vault_state)[``"LOGGED_IN"``] \| typeof [`VAULT_STATE`](API.md#vault_state)[``"CONNECTED"``]

#### Defined in

[cloud-vault-client/src/ts/vault-state.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/cloud-vault-client/src/ts/vault-state.ts#L10)

## Variables

### VAULT\_STATE

• `Const` **VAULT\_STATE**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `CONNECTED` | ``3`` |
| `INITIALIZED` | ``1`` |
| `LOGGED_IN` | ``2`` |
| `NOT_INITIALIZED` | ``0`` |

#### Defined in

[cloud-vault-client/src/ts/vault-state.ts:3](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/cloud-vault-client/src/ts/vault-state.ts#L3)

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

[cloud-vault-client/src/ts/error.ts:95](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/cloud-vault-client/src/ts/error.ts#L95)

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

[cloud-vault-client/src/ts/key-manager.ts:77](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/cloud-vault-client/src/ts/key-manager.ts#L77)

▸ **deriveKey**(`key`, `opts`): `Promise`<`KeyObject`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `key` | `KeyObject` |
| `opts` | [`KeyDerivationOptions`](interfaces/KeyDerivationOptions.md) |

#### Returns

`Promise`<`KeyObject`\>

#### Defined in

[cloud-vault-client/src/ts/key-manager.ts:78](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/cloud-vault-client/src/ts/key-manager.ts#L78)
