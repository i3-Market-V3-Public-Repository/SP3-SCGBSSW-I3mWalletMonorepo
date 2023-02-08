# @i3m/cloud-vault-client - v2.5.7

A TypeScript/JavaScript implementation of a client for the i3M-Wallet Cloud-Vault server

## Table of contents

### Classes

- [KeyManager](classes/KeyManager.md)
- [SecretKey](classes/SecretKey.md)
- [VaultClient](classes/VaultClient.md)

### Interfaces

- [KeyDerivationOptions](interfaces/KeyDerivationOptions.md)
- [ScryptOptions](interfaces/ScryptOptions.md)
- [VaultConnError](interfaces/VaultConnError.md)
- [VaultEvent](interfaces/VaultEvent.md)
- [VaultStorage](interfaces/VaultStorage.md)

### Functions

- [deriveKey](API.md#derivekey)

## Functions

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

[cloud-vault-client/src/ts/key-manager.ts:74](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2705a55/packages/cloud-vault-client/src/ts/key-manager.ts#L74)

▸ **deriveKey**(`key`, `opts`): `Promise`<`KeyObject`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `key` | `KeyObject` |
| `opts` | [`KeyDerivationOptions`](interfaces/KeyDerivationOptions.md) |

#### Returns

`Promise`<`KeyObject`\>

#### Defined in

[cloud-vault-client/src/ts/key-manager.ts:75](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2705a55/packages/cloud-vault-client/src/ts/key-manager.ts#L75)
