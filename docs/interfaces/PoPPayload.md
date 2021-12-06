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
- [por](PoPPayload.md#por)
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

[src/ts/types.ts:87](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/b9ca89b/src/ts/types.ts#L87)

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

[src/ts/types.ts:102](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/b9ca89b/src/ts/types.ts#L102)

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

### por

• **por**: `string`

#### Defined in

[src/ts/types.ts:104](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/b9ca89b/src/ts/types.ts#L104)

___

### proofType

• **proofType**: ``"PoP"``

#### Defined in

[src/ts/types.ts:103](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/b9ca89b/src/ts/types.ts#L103)

___

### secret

• **secret**: `string`

#### Defined in

[src/ts/types.ts:105](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/b9ca89b/src/ts/types.ts#L105)

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

[src/ts/types.ts:106](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/b9ca89b/src/ts/types.ts#L106)
