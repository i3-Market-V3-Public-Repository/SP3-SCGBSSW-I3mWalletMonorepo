# @i3m/cloud-vault-client - v2.6.2

A TypeScript/JavaScript implementation of a client for the i3M-Wallet Cloud-Vault server

## Table of contents

### Classes

- [KeyManager](classes/KeyManager.md)
- [Request](classes/Request.md)
- [SecretKey](classes/SecretKey.md)
- [VaultClient](classes/VaultClient.md)
- [VaultError](classes/VaultError.md)

### Interfaces

- [KeyDerivationOptions](interfaces/KeyDerivationOptions.md)
- [PasswordStrengthOptions](interfaces/PasswordStrengthOptions.md)
- [RetryOptions](interfaces/RetryOptions.md)
- [ScryptOptions](interfaces/ScryptOptions.md)
- [VaultClientOpts](interfaces/VaultClientOpts.md)
- [VaultStorage](interfaces/VaultStorage.md)

### Type Aliases

- [CbOnEventFn](API.md#cboneventfn)
- [DataForError](API.md#dataforerror)
- [VaultErrorData](API.md#vaulterrordata)
- [VaultErrorName](API.md#vaulterrorname)
- [VaultState](API.md#vaultstate)

### Variables

- [VAULT\_STATE](API.md#vault_state)
- [defaultPasswordStrengthOptions](API.md#defaultpasswordstrengthoptions)

### Functions

- [checkErrorType](API.md#checkerrortype)
- [deriveKey](API.md#derivekey)
- [passwordCheck](API.md#passwordcheck)

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

[cloud-vault-client/src/ts/vault-client.ts:16](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e4b61ed6/packages/cloud-vault-client/src/ts/vault-client.ts#L16)

___

### DataForError

Ƭ **DataForError**<`T`\>: [`VaultErrorData`](API.md#vaulterrordata)[`T`]

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends [`VaultErrorName`](API.md#vaulterrorname) |

#### Defined in

[cloud-vault-client/src/ts/error.ts:47](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e4b61ed6/packages/cloud-vault-client/src/ts/error.ts#L47)

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
| `http-request-canceled` | { `request`: { `data?`: `any` ; `headers?`: { `[header: string]`: `string`;  } ; `method?`: `string` ; `url?`: `string`  }  } |
| `http-request-canceled.request` | { `data?`: `any` ; `headers?`: { `[header: string]`: `string`;  } ; `method?`: `string` ; `url?`: `string`  } |
| `http-request-canceled.request.data?` | `any` |
| `http-request-canceled.request.headers?` | { `[header: string]`: `string`;  } |
| `http-request-canceled.request.method?` | `string` |
| `http-request-canceled.request.url?` | `string` |
| `invalid-credentials` | `any` |
| `invalid-timestamp` | `any` |
| `no-uploaded-storage` | `any` |
| `not-initialized` | `any` |
| `quota-exceeded` | `string` |
| `sse-connection-error` | `any` |
| `unauthorized` | `any` |
| `unknown` | `any` |
| `validation` | { `data?`: `any` ; `description?`: `string`  } |
| `validation.data?` | `any` |
| `validation.description?` | `string` |
| `weak-password` | `string` |

#### Defined in

[cloud-vault-client/src/ts/error.ts:5](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e4b61ed6/packages/cloud-vault-client/src/ts/error.ts#L5)

___

### VaultErrorName

Ƭ **VaultErrorName**: keyof [`VaultErrorData`](API.md#vaulterrordata)

#### Defined in

[cloud-vault-client/src/ts/error.ts:46](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e4b61ed6/packages/cloud-vault-client/src/ts/error.ts#L46)

___

### VaultState

Ƭ **VaultState**: typeof [`VAULT_STATE`](API.md#vault_state)[``"NOT_INITIALIZED"``] \| typeof [`VAULT_STATE`](API.md#vault_state)[``"INITIALIZED"``] \| typeof [`VAULT_STATE`](API.md#vault_state)[``"LOGGED_IN"``] \| typeof [`VAULT_STATE`](API.md#vault_state)[``"CONNECTED"``]

#### Defined in

[cloud-vault-client/src/ts/vault-state.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e4b61ed6/packages/cloud-vault-client/src/ts/vault-state.ts#L10)

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

[cloud-vault-client/src/ts/vault-state.ts:3](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e4b61ed6/packages/cloud-vault-client/src/ts/vault-state.ts#L3)

___

### defaultPasswordStrengthOptions

• `Const` **defaultPasswordStrengthOptions**: `Required`<[`PasswordStrengthOptions`](interfaces/PasswordStrengthOptions.md)\>

#### Defined in

[cloud-vault-client/src/ts/password-checker.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e4b61ed6/packages/cloud-vault-client/src/ts/password-checker.ts#L12)

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

[cloud-vault-client/src/ts/error.ts:107](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e4b61ed6/packages/cloud-vault-client/src/ts/error.ts#L107)

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

[cloud-vault-client/src/ts/key-manager.ts:77](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e4b61ed6/packages/cloud-vault-client/src/ts/key-manager.ts#L77)

▸ **deriveKey**(`key`, `opts`): `Promise`<`KeyObject`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `key` | `KeyObject` |
| `opts` | [`KeyDerivationOptions`](interfaces/KeyDerivationOptions.md) |

#### Returns

`Promise`<`KeyObject`\>

#### Defined in

[cloud-vault-client/src/ts/key-manager.ts:78](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e4b61ed6/packages/cloud-vault-client/src/ts/key-manager.ts#L78)

___

### passwordCheck

▸ **passwordCheck**(`password`, `options?`): `void`

#### Parameters

| Name | Type |
| :------ | :------ |
| `password` | `string` |
| `options?` | [`PasswordStrengthOptions`](interfaces/PasswordStrengthOptions.md) |

#### Returns

`void`

#### Defined in

[cloud-vault-client/src/ts/password-checker.ts:21](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e4b61ed6/packages/cloud-vault-client/src/ts/password-checker.ts#L21)
