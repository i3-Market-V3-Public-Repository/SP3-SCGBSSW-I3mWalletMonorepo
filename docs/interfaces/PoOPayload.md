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

[src/ts/types.ts:53](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/cd48614/src/ts/types.ts#L53)

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

[src/ts/types.ts:57](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/cd48614/src/ts/types.ts#L57)

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

[src/ts/types.ts:58](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/cd48614/src/ts/types.ts#L58)

___

### sub

• `Optional` **sub**: `string`

#### Inherited from

ProofCommonPayload.sub

#### Defined in

node_modules/jose/dist/types/types.d.ts:214
