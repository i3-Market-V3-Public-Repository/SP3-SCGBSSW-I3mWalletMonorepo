# Interface: PoRPayload

## Hierarchy

- `ProofCommonPayload`

  ↳ **`PoRPayload`**

## Table of contents

### Properties

- [aud](PoRPayload.md#aud)
- [exchange](PoRPayload.md#exchange)
- [exp](PoRPayload.md#exp)
- [iat](PoRPayload.md#iat)
- [iss](PoRPayload.md#iss)
- [jti](PoRPayload.md#jti)
- [nbf](PoRPayload.md#nbf)
- [pooDgst](PoRPayload.md#poodgst)
- [proofType](PoRPayload.md#prooftype)
- [sub](PoRPayload.md#sub)

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

[src/ts/types.ts:53](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/types.ts#L53)

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

• **iss**: ``"dest"``

#### Overrides

ProofCommonPayload.iss

#### Defined in

[src/ts/types.ts:62](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/types.ts#L62)

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

### pooDgst

• **pooDgst**: `string`

#### Defined in

[src/ts/types.ts:64](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/types.ts#L64)

___

### proofType

• **proofType**: ``"PoR"``

#### Defined in

[src/ts/types.ts:63](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/types.ts#L63)

___

### sub

• `Optional` **sub**: `string`

#### Inherited from

ProofCommonPayload.sub

#### Defined in

node_modules/jose/dist/types/types.d.ts:214
