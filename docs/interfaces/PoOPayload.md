# Interface: PoOPayload

## Hierarchy

- `ProofCommonPayload`

  ↳ **`PoOPayload`**

## Table of contents

### Properties

- [aud](PoOPayload.md#aud)
- [exchange](PoOPayload.md#exchange)
- [exp](PoOPayload.md#exp)
- [iat](PoOPayload.md#iat)
- [iss](PoOPayload.md#iss)
- [jti](PoOPayload.md#jti)
- [nbf](PoOPayload.md#nbf)
- [proofType](PoOPayload.md#prooftype)
- [sub](PoOPayload.md#sub)

## Properties

### aud

• `Optional` **aud**: `string` \| `string`[]

#### Inherited from

ProofCommonPayload.aud

#### Defined in

node_modules/jose/dist/types/types.d.ts:215

___

### exchange

• **exchange**: [`DataExchangeInit`](DataExchangeInit.md)

#### Inherited from

ProofCommonPayload.exchange

#### Defined in

[src/ts/types.ts:87](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/types.ts#L87)

___

### exp

• `Optional` **exp**: `number`

#### Inherited from

ProofCommonPayload.exp

#### Defined in

node_modules/jose/dist/types/types.d.ts:218

___

### iat

• `Optional` **iat**: `number`

#### Inherited from

ProofCommonPayload.iat

#### Defined in

node_modules/jose/dist/types/types.d.ts:219

___

### iss

• **iss**: ``"orig"``

#### Overrides

ProofCommonPayload.iss

#### Defined in

[src/ts/types.ts:91](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/types.ts#L91)

___

### jti

• `Optional` **jti**: `string`

#### Inherited from

ProofCommonPayload.jti

#### Defined in

node_modules/jose/dist/types/types.d.ts:216

___

### nbf

• `Optional` **nbf**: `number`

#### Inherited from

ProofCommonPayload.nbf

#### Defined in

node_modules/jose/dist/types/types.d.ts:217

___

### proofType

• **proofType**: ``"PoO"``

#### Defined in

[src/ts/types.ts:92](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/types.ts#L92)

___

### sub

• `Optional` **sub**: `string`

#### Inherited from

ProofCommonPayload.sub

#### Defined in

node_modules/jose/dist/types/types.d.ts:214
