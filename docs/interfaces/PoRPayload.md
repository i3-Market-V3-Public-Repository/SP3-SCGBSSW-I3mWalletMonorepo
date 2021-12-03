# Interface: PoRPayload

## Hierarchy

- `ProofCommonPayload`

  ↳ **`PoRPayload`**

## Table of contents

### Properties

- [aud](PoRPayload.md#aud)
- [dataExchange](PoRPayload.md#dataexchange)
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

### dataExchange

• **dataExchange**: [`DataExchangeInit`](DataExchangeInit.md)

#### Inherited from

ProofCommonPayload.dataExchange

#### Defined in

[src/ts/types.ts:36](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/d1778d3/src/ts/types.ts#L36)

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

[src/ts/types.ts:45](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/d1778d3/src/ts/types.ts#L45)

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

[src/ts/types.ts:47](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/d1778d3/src/ts/types.ts#L47)

___

### proofType

• **proofType**: ``"PoR"``

#### Defined in

[src/ts/types.ts:46](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/d1778d3/src/ts/types.ts#L46)

___

### sub

• `Optional` **sub**: `string`

#### Inherited from

ProofCommonPayload.sub

#### Defined in

node_modules/jose/dist/types/types.d.ts:214
