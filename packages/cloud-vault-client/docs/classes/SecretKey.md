# Class: SecretKey

## Table of contents

### Constructors

- [constructor](SecretKey.md#constructor)

### Properties

- [alg](SecretKey.md#alg)

### Methods

- [decrypt](SecretKey.md#decrypt)
- [encrypt](SecretKey.md#encrypt)

## Constructors

### constructor

• **new SecretKey**(`key`, `alg`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `key` | `KeyObject` |
| `alg` | ``"aes-192-gcm"`` \| ``"aes-256-gcm"`` |

#### Defined in

[cloud-vault-client/src/ts/secret-key.ts:8](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/0a37054/packages/cloud-vault-client/src/ts/secret-key.ts#L8)

## Properties

### alg

• `Readonly` **alg**: ``"aes-192-gcm"`` \| ``"aes-256-gcm"``

#### Defined in

[cloud-vault-client/src/ts/secret-key.ts:6](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/0a37054/packages/cloud-vault-client/src/ts/secret-key.ts#L6)

## Methods

### decrypt

▸ **decrypt**(`input`): `Buffer`

#### Parameters

| Name | Type |
| :------ | :------ |
| `input` | `Buffer` |

#### Returns

`Buffer`

#### Defined in

[cloud-vault-client/src/ts/secret-key.ts:30](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/0a37054/packages/cloud-vault-client/src/ts/secret-key.ts#L30)

___

### encrypt

▸ **encrypt**(`input`): `Buffer`

#### Parameters

| Name | Type |
| :------ | :------ |
| `input` | `Buffer` |

#### Returns

`Buffer`

#### Defined in

[cloud-vault-client/src/ts/secret-key.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/0a37054/packages/cloud-vault-client/src/ts/secret-key.ts#L13)
