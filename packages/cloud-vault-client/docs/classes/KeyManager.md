# Class: KeyManager

## Table of contents

### Constructors

- [constructor](KeyManager.md#constructor)

### Properties

- [derivationOptions](KeyManager.md#derivationoptions)
- [initialized](KeyManager.md#initialized)
- [username](KeyManager.md#username)

### Accessors

- [authKey](KeyManager.md#authkey)
- [encKey](KeyManager.md#enckey)

## Constructors

### constructor

• **new KeyManager**(`username`, `password`, `opts`)

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `username` | `string` | - |
| `password` | `string` | - |
| `opts` | `Object` | - |
| `opts.auth` | `KeyDerivationOptions` | - |
| `opts.enc` | `Object` | - |
| `opts.enc.alg` | ``"scrypt"`` | - |
| `opts.enc.alg_options` | `ScryptOptions` | - |
| `opts.enc.derived_key_length` | `number` | Desired key length in bytes |
| `opts.enc.enc_algorithm` | ``"aes-192-gcm"`` \| ``"aes-256-gcm"`` | example: aes-256-gcm |
| `opts.enc.input` | ``"password"`` \| ``"master-key"`` | example: password |
| `opts.enc.salt_hashing_algorithm` | ``"sha3-256"`` \| ``"sha3-384"`` \| ``"sha3-512"`` \| ``"sha256"`` \| ``"sha384"`` \| ``"sha512"`` | Since salts are length contrained, and saltPattern creates salts with an arbitrary length, the input salt is hashed with the provided hash algorithm. example: sha3-512 |
| `opts.enc.salt_pattern` | `string` | Describes the salt pattern to use when deriving the key from a password. It is a UTF-8 string, where variables to replace wrapped in curly braces. The salt is a concatenation of key_name, server_id and username. The length is not important since the provided salt will be hashed before being used (see saltHashingAlgorithm) example: master9u8tHv8_s-QsG8CxuAefhg{username} |
| `opts.master` | `KeyDerivationOptions` | - |

#### Defined in

[cloud-vault-client/src/ts/key-manager.ts:27](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/cloud-vault-client/src/ts/key-manager.ts#L27)

## Properties

### derivationOptions

• **derivationOptions**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `auth` | `KeyDerivationOptions` |
| `enc` | { `alg`: ``"scrypt"`` ; `alg_options`: `ScryptOptions` ; `derived_key_length`: `number` ; `enc_algorithm`: ``"aes-192-gcm"`` \| ``"aes-256-gcm"`` ; `input`: ``"password"`` \| ``"master-key"`` ; `salt_hashing_algorithm`: ``"sha3-256"`` \| ``"sha3-384"`` \| ``"sha3-512"`` \| ``"sha256"`` \| ``"sha384"`` \| ``"sha512"`` ; `salt_pattern`: `string`  } |
| `enc.alg` | ``"scrypt"`` |
| `enc.alg_options` | `ScryptOptions` |
| `enc.derived_key_length` | `number` |
| `enc.enc_algorithm` | ``"aes-192-gcm"`` \| ``"aes-256-gcm"`` |
| `enc.input` | ``"password"`` \| ``"master-key"`` |
| `enc.salt_hashing_algorithm` | ``"sha3-256"`` \| ``"sha3-384"`` \| ``"sha3-512"`` \| ``"sha256"`` \| ``"sha384"`` \| ``"sha512"`` |
| `enc.salt_pattern` | `string` |
| `master` | `KeyDerivationOptions` |

#### Defined in

[cloud-vault-client/src/ts/key-manager.ts:23](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/cloud-vault-client/src/ts/key-manager.ts#L23)

___

### initialized

• **initialized**: `Promise`<`void`\>

#### Defined in

[cloud-vault-client/src/ts/key-manager.ts:24](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/cloud-vault-client/src/ts/key-manager.ts#L24)

___

### username

• **username**: `string`

#### Defined in

[cloud-vault-client/src/ts/key-manager.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/cloud-vault-client/src/ts/key-manager.ts#L22)

## Accessors

### authKey

• `get` **authKey**(): `string`

#### Returns

`string`

#### Defined in

[cloud-vault-client/src/ts/key-manager.ts:52](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/cloud-vault-client/src/ts/key-manager.ts#L52)

___

### encKey

• `get` **encKey**(): [`SecretKey`](SecretKey.md)

#### Returns

[`SecretKey`](SecretKey.md)

#### Defined in

[cloud-vault-client/src/ts/key-manager.ts:59](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/cloud-vault-client/src/ts/key-manager.ts#L59)
