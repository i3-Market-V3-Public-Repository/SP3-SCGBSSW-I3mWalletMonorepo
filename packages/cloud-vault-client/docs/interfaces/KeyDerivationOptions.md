# Interface: KeyDerivationOptions

## Hierarchy

- `KeyDerivationOptions`

  ↳ **`KeyDerivationOptions`**

## Table of contents

### Properties

- [alg](KeyDerivationOptions.md#alg)
- [alg\_options](KeyDerivationOptions.md#alg_options)
- [derived\_key\_length](KeyDerivationOptions.md#derived_key_length)
- [input](KeyDerivationOptions.md#input)
- [salt](KeyDerivationOptions.md#salt)
- [salt\_hashing\_algorithm](KeyDerivationOptions.md#salt_hashing_algorithm)
- [salt\_pattern](KeyDerivationOptions.md#salt_pattern)

## Properties

### alg

• **alg**: ``"scrypt"``

#### Inherited from

OpenApiComponents.Schemas.KeyDerivationOptions.alg

#### Defined in

[cloud-vault-server/types/openapi.d.ts:144](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/cloud-vault-server/types/openapi.d.ts#L144)

___

### alg\_options

• **alg\_options**: `ScryptOptions`

#### Inherited from

OpenApiComponents.Schemas.KeyDerivationOptions.alg\_options

#### Defined in

[cloud-vault-server/types/openapi.d.ts:172](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/cloud-vault-server/types/openapi.d.ts#L172)

___

### derived\_key\_length

• **derived\_key\_length**: `number`

Desired key length in bytes

#### Inherited from

OpenApiComponents.Schemas.KeyDerivationOptions.derived\_key\_length

#### Defined in

[cloud-vault-server/types/openapi.d.ts:148](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/cloud-vault-server/types/openapi.d.ts#L148)

___

### input

• **input**: ``"password"`` \| ``"master-key"``

example:
password

#### Inherited from

OpenApiComponents.Schemas.KeyDerivationOptions.input

#### Defined in

[cloud-vault-server/types/openapi.d.ts:153](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/cloud-vault-server/types/openapi.d.ts#L153)

___

### salt

• **salt**: `Buffer`

#### Defined in

[cloud-vault-client/src/ts/key-manager.ts:16](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/cloud-vault-client/src/ts/key-manager.ts#L16)

___

### salt\_hashing\_algorithm

• **salt\_hashing\_algorithm**: ``"sha3-256"`` \| ``"sha3-384"`` \| ``"sha3-512"`` \| ``"sha256"`` \| ``"sha384"`` \| ``"sha512"``

Since salts are length contrained, and saltPattern creates salts with an arbitrary length, the input salt is hashed with the provided hash algorithm.

example:
sha3-512

#### Inherited from

OpenApiComponents.Schemas.KeyDerivationOptions.salt\_hashing\_algorithm

#### Defined in

[cloud-vault-server/types/openapi.d.ts:171](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/cloud-vault-server/types/openapi.d.ts#L171)

___

### salt\_pattern

• **salt\_pattern**: `string`

Describes the salt pattern to use when deriving the key from a password. It is a UTF-8 string, where variables to replace wrapped in curly braces.

The salt is a concatenation of key_name, server_id and username.

The length is not important since the provided salt will be hashed before being used (see saltHashingAlgorithm)

example:
master9u8tHv8_s-QsG8CxuAefhg{username}

#### Inherited from

OpenApiComponents.Schemas.KeyDerivationOptions.salt\_pattern

#### Defined in

[cloud-vault-server/types/openapi.d.ts:164](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/cloud-vault-server/types/openapi.d.ts#L164)
