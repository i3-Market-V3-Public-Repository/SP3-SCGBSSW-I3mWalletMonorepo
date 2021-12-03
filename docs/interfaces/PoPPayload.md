# Interface: PoPPayload

## Hierarchy

- `ProofCommonPayload`

  ↳ **`PoPPayload`**

## Table of contents

### Properties

- [aud](PoPPayload.md#aud)
- [exchange](PoPPayload.md#exchange)
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

• **iss**: ``"orig"``

#### Overrides

ProofCommonPayload.iss

#### Defined in

[src/ts/types.ts:68](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/types.ts#L68)

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

[src/ts/types.ts:70](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/types.ts#L70)

___

### proofType

• **proofType**: ``"PoP"``

#### Defined in

[src/ts/types.ts:69](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/types.ts#L69)

___

### secret

• **secret**: `string`

#### Defined in

[src/ts/types.ts:71](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/types.ts#L71)

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

[src/ts/types.ts:72](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/types.ts#L72)
