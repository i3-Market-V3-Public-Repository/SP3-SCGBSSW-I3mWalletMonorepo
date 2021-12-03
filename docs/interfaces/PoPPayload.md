# Interface: PoPPayload

## Hierarchy

- `ProofCommonPayload`

  ↳ **`PoPPayload`**

## Table of contents

### Properties

- [aud](PoPPayload.md#aud)
- [dataExchange](PoPPayload.md#dataexchange)
- [exp](PoPPayload.md#exp)
- [iat](PoPPayload.md#iat)
- [iss](PoPPayload.md#iss)
- [jti](PoPPayload.md#jti)
- [nbf](PoPPayload.md#nbf)
- [porDgst](PoPPayload.md#pordgst)
- [proofType](PoPPayload.md#prooftype)
- [secret](PoPPayload.md#secret)
- [sub](PoPPayload.md#sub)
- [verificationCode](PoPPayload.md#verificationcode)

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

• **iss**: ``"orig"``

#### Overrides

ProofCommonPayload.iss

#### Defined in

[src/ts/types.ts:51](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/d1778d3/src/ts/types.ts#L51)

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

### porDgst

• **porDgst**: `string`

#### Defined in

[src/ts/types.ts:53](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/d1778d3/src/ts/types.ts#L53)

___

### proofType

• **proofType**: ``"PoP"``

#### Defined in

[src/ts/types.ts:52](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/d1778d3/src/ts/types.ts#L52)

___

### secret

• **secret**: `string`

#### Defined in

[src/ts/types.ts:54](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/d1778d3/src/ts/types.ts#L54)

___

### sub

• `Optional` **sub**: `string`

#### Inherited from

ProofCommonPayload.sub

#### Defined in

node_modules/jose/dist/types/types.d.ts:214

___

### verificationCode

• **verificationCode**: `string`

#### Defined in

[src/ts/types.ts:55](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/d1778d3/src/ts/types.ts#L55)
