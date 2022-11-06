# Interface: DataExchangeAgreement

## Hierarchy

- `DataExchangeAgreement`

  ↳ **`DataExchangeAgreement`**

## Table of contents

### Properties

- [dest](DataExchangeAgreement.md#dest)
- [encAlg](DataExchangeAgreement.md#encalg)
- [hashAlg](DataExchangeAgreement.md#hashalg)
- [ledgerContractAddress](DataExchangeAgreement.md#ledgercontractaddress)
- [ledgerSignerAddress](DataExchangeAgreement.md#ledgersigneraddress)
- [orig](DataExchangeAgreement.md#orig)
- [pooToPopDelay](DataExchangeAgreement.md#pootopopdelay)
- [pooToPorDelay](DataExchangeAgreement.md#pootopordelay)
- [pooToSecretDelay](DataExchangeAgreement.md#pootosecretdelay)
- [schema](DataExchangeAgreement.md#schema)
- [signingAlg](DataExchangeAgreement.md#signingalg)

## Properties

### dest

• **dest**: `string`

A stringified JWK with alphabetically sorted claims
example:
{"alg":"ES256","crv":"P-256","kty":"EC","x":"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k","y":"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4"}

#### Inherited from

WalletComponents.Schemas.DataExchangeAgreement.dest

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:286

___

### encAlg

• **encAlg**: ``"A128GCM"`` \| ``"A256GCM"``

example:
A256GCM

#### Inherited from

WalletComponents.Schemas.DataExchangeAgreement.encAlg

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:291

___

### hashAlg

• **hashAlg**: ``"SHA-256"`` \| ``"SHA-384"`` \| ``"SHA-512"``

example:
SHA-256

#### Inherited from

WalletComponents.Schemas.DataExchangeAgreement.hashAlg

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:301

___

### ledgerContractAddress

• **ledgerContractAddress**: `string`

Ethereum Address in EIP-55 format (with checksum)
example:
0x71C7656EC7ab88b098defB751B7401B5f6d8976F

#### Inherited from

WalletComponents.Schemas.DataExchangeAgreement.ledgerContractAddress

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:307

___

### ledgerSignerAddress

• **ledgerSignerAddress**: `string`

Ethereum Address in EIP-55 format (with checksum)
example:
0x71C7656EC7ab88b098defB751B7401B5f6d8976F

#### Inherited from

WalletComponents.Schemas.DataExchangeAgreement.ledgerSignerAddress

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:313

___

### orig

• **orig**: `string`

A stringified JWK with alphabetically sorted claims
example:
{"alg":"ES256","crv":"P-256","kty":"EC","x":"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo","y":"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0"}

#### Inherited from

WalletComponents.Schemas.DataExchangeAgreement.orig

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:280

___

### pooToPopDelay

• **pooToPopDelay**: `number`

Maximum acceptable time in milliseconds between issued PoO and issued PoP
example:
20000

#### Inherited from

WalletComponents.Schemas.DataExchangeAgreement.pooToPopDelay

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:325

___

### pooToPorDelay

• **pooToPorDelay**: `number`

Maximum acceptable time in milliseconds between issued PoO and verified PoR
example:
10000

#### Inherited from

WalletComponents.Schemas.DataExchangeAgreement.pooToPorDelay

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:319

___

### pooToSecretDelay

• **pooToSecretDelay**: `number`

Maximum acceptable time between issued PoO and secret published on the ledger
example:
180000

#### Inherited from

WalletComponents.Schemas.DataExchangeAgreement.pooToSecretDelay

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:331

___

### schema

• `Optional` **schema**: `string`

A stringified JSON-LD schema describing the data format

#### Inherited from

WalletComponents.Schemas.DataExchangeAgreement.schema

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:335

___

### signingAlg

• **signingAlg**: ``"ES256"`` \| ``"ES384"`` \| ``"ES512"``

example:
ES256

#### Inherited from

WalletComponents.Schemas.DataExchangeAgreement.signingAlg

#### Defined in

node_modules/@i3m/wallet-desktop-openapi/types/openapi.d.ts:296
