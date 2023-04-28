# Interface: DataExchange

## Hierarchy

- `DataExchange`

  ↳ **`DataExchange`**

## Table of contents

### Properties

- [blockCommitment](DataExchange.md#blockcommitment)
- [cipherblockDgst](DataExchange.md#cipherblockdgst)
- [dest](DataExchange.md#dest)
- [encAlg](DataExchange.md#encalg)
- [hashAlg](DataExchange.md#hashalg)
- [id](DataExchange.md#id)
- [ledgerContractAddress](DataExchange.md#ledgercontractaddress)
- [ledgerSignerAddress](DataExchange.md#ledgersigneraddress)
- [orig](DataExchange.md#orig)
- [pooToPopDelay](DataExchange.md#pootopopdelay)
- [pooToPorDelay](DataExchange.md#pootopordelay)
- [pooToSecretDelay](DataExchange.md#pootosecretdelay)
- [schema](DataExchange.md#schema)
- [secretCommitment](DataExchange.md#secretcommitment)
- [signingAlg](DataExchange.md#signingalg)

## Properties

### blockCommitment

• **blockCommitment**: `string`

hash of the plaintext block in base64url with no padding

#### Inherited from

WalletComponents.Schemas.DataExchange.blockCommitment

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:109

___

### cipherblockDgst

• **cipherblockDgst**: `string`

hash of the cipherblock in base64url with no padding

#### Inherited from

WalletComponents.Schemas.DataExchange.cipherblockDgst

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:105

___

### dest

• **dest**: `string`

A stringified JWK with alphabetically sorted claims
example:
{"alg":"ES256","crv":"P-256","kty":"EC","x":"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k","y":"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4"}

#### Inherited from

WalletComponents.Schemas.DataExchange.dest

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:52

___

### encAlg

• **encAlg**: ``"A128GCM"`` \| ``"A256GCM"``

example:
A256GCM

#### Inherited from

WalletComponents.Schemas.DataExchange.encAlg

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:57

___

### hashAlg

• **hashAlg**: ``"SHA-256"`` \| ``"SHA-384"`` \| ``"SHA-512"``

example:
SHA-256

#### Inherited from

WalletComponents.Schemas.DataExchange.hashAlg

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:67

___

### id

• **id**: `string`

#### Defined in

[src/ts/types.ts:90](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/00dbbfe/src/ts/types.ts#L90)

___

### ledgerContractAddress

• **ledgerContractAddress**: `string`

#### Inherited from

WalletComponents.Schemas.DataExchange.ledgerContractAddress

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:68

___

### ledgerSignerAddress

• **ledgerSignerAddress**: `string`

#### Inherited from

WalletComponents.Schemas.DataExchange.ledgerSignerAddress

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:74

___

### orig

• **orig**: `string`

A stringified JWK with alphabetically sorted claims
example:
{"alg":"ES256","crv":"P-256","kty":"EC","x":"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo","y":"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0"}

#### Inherited from

WalletComponents.Schemas.DataExchange.orig

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:46

___

### pooToPopDelay

• **pooToPopDelay**: `number`

Maximum acceptable time in milliseconds between issued PoO and issued PoP
example:
20000

#### Inherited from

WalletComponents.Schemas.DataExchange.pooToPopDelay

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:91

___

### pooToPorDelay

• **pooToPorDelay**: `number`

Maximum acceptable time in milliseconds between issued PoO and verified PoR
example:
10000

#### Inherited from

WalletComponents.Schemas.DataExchange.pooToPorDelay

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:85

___

### pooToSecretDelay

• **pooToSecretDelay**: `number`

Maximum acceptable time between issued PoO and secret published on the ledger
example:
180000

#### Inherited from

WalletComponents.Schemas.DataExchange.pooToSecretDelay

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:97

___

### schema

• `Optional` **schema**: `string`

A stringified JSON-LD schema describing the data format

#### Inherited from

WalletComponents.Schemas.DataExchange.schema

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:101

___

### secretCommitment

• **secretCommitment**: `string`

ash of the secret that can be used to decrypt the block in base64url with no padding

#### Inherited from

WalletComponents.Schemas.DataExchange.secretCommitment

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:113

___

### signingAlg

• **signingAlg**: ``"ES256"`` \| ``"ES384"`` \| ``"ES512"``

example:
ES256

#### Inherited from

WalletComponents.Schemas.DataExchange.signingAlg

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:62
