# Interface: KeyDerivationOptions

## Hierarchy

- `KeyDerivationOptions`

  ↳ **`KeyDerivationOptions`**

## Table of contents

### Properties

- [alg](KeyDerivationOptions.md#alg)
- [algOptions](KeyDerivationOptions.md#algoptions)
- [derivedKeyLength](KeyDerivationOptions.md#derivedkeylength)
- [input](KeyDerivationOptions.md#input)
- [salt](KeyDerivationOptions.md#salt)
- [saltHashingAlgorithm](KeyDerivationOptions.md#salthashingalgorithm)
- [saltPattern](KeyDerivationOptions.md#saltpattern)

## Properties

### alg

• **alg**: ``"scrypt"``

#### Inherited from

OpenApiComponents.Schemas.KeyDerivationOptions.alg

#### Defined in

[cloud-vault-server/types/openapi.d.ts:120](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/ec1c8b6/packages/cloud-vault-server/types/openapi.d.ts#L120)

___

### algOptions

• **algOptions**: `ScryptOptions`

#### Inherited from

OpenApiComponents.Schemas.KeyDerivationOptions.algOptions

#### Defined in

[cloud-vault-server/types/openapi.d.ts:148](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/ec1c8b6/packages/cloud-vault-server/types/openapi.d.ts#L148)

___

### derivedKeyLength

• **derivedKeyLength**: `number`

Desired key length in bytes

#### Inherited from

OpenApiComponents.Schemas.KeyDerivationOptions.derivedKeyLength

#### Defined in

[cloud-vault-server/types/openapi.d.ts:124](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/ec1c8b6/packages/cloud-vault-server/types/openapi.d.ts#L124)

___

### input

• **input**: ``"password"`` \| ``"master-key"``

example:
password

#### Inherited from

OpenApiComponents.Schemas.KeyDerivationOptions.input

#### Defined in

[cloud-vault-server/types/openapi.d.ts:129](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/ec1c8b6/packages/cloud-vault-server/types/openapi.d.ts#L129)

___

### salt

• **salt**: `Buffer`

#### Defined in

[cloud-vault-client/src/ts/key-manager.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/ec1c8b6/packages/cloud-vault-client/src/ts/key-manager.ts#L12)

___

### saltHashingAlgorithm

• **saltHashingAlgorithm**: ``"sha3-256"`` \| ``"sha3-384"`` \| ``"sha3-512"``

Since salts are length contrained, and saltPattern creates salts with an arbitrary length, the input salt is hashed with the provided hash algorithm.

example:
sha3-512

#### Inherited from

OpenApiComponents.Schemas.KeyDerivationOptions.saltHashingAlgorithm

#### Defined in

[cloud-vault-server/types/openapi.d.ts:147](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/ec1c8b6/packages/cloud-vault-server/types/openapi.d.ts#L147)

___

### saltPattern

• **saltPattern**: `string`

Describes the salt pattern to use when deriving the key from a password. It is a UTF-8 string, where variables to replace wrapped in curly braces.

The salt is a concatenation of key_name, server_id and username.

The length is not important since the provided salt will be hashed before being used (see saltHashingAlgorithm)

example:
master9u8tHv8_s-QsG8CxuAefhg{username}

#### Inherited from

OpenApiComponents.Schemas.KeyDerivationOptions.saltPattern

#### Defined in

[cloud-vault-server/types/openapi.d.ts:140](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/ec1c8b6/packages/cloud-vault-server/types/openapi.d.ts#L140)
