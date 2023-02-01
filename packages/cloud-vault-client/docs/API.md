# @i3m/cloud-vault-client - v2.5.6

A TypeScript/JavaScript implementation of a client for the i3M-Wallet Cloud-Vault server

## Table of contents

### Classes

- [KeyManager](classes/KeyManager.md)
- [VaultClient](classes/VaultClient.md)

### Interfaces

- [DerivationOptions](interfaces/DerivationOptions.md)
- [KdfOptions](interfaces/KdfOptions.md)
- [ScryptOptions](interfaces/ScryptOptions.md)

### Functions

- [deriveKey](API.md#derivekey)

## Functions

### deriveKey

▸ **deriveKey**(`password`, `opts`, `returnBuffer?`): `Promise`<`KeyObject`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `password` | `BinaryLike` |
| `opts` | [`KdfOptions`](interfaces/KdfOptions.md) |
| `returnBuffer?` | ``false`` |

#### Returns

`Promise`<`KeyObject`\>

#### Defined in

src/ts/key-manager.ts:57

▸ **deriveKey**(`password`, `opts`, `returnBuffer`): `Promise`<`Buffer`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `password` | `BinaryLike` |
| `opts` | [`KdfOptions`](interfaces/KdfOptions.md) |
| `returnBuffer` | ``true`` |

#### Returns

`Promise`<`Buffer`\>

#### Defined in

src/ts/key-manager.ts:58
