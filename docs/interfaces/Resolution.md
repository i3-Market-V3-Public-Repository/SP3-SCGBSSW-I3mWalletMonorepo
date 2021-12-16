# Interface: Resolution

## Hierarchy

- `JWTPayload`

  ↳ **`Resolution`**

  ↳↳ [`VerificationResolution`](VerificationResolution.md)

  ↳↳ [`DisputeResolution`](DisputeResolution.md)

## Table of contents

### Properties

- [aud](Resolution.md#aud)
- [dataExchangeId](Resolution.md#dataexchangeid)
- [exp](Resolution.md#exp)
- [iat](Resolution.md#iat)
- [iss](Resolution.md#iss)
- [jti](Resolution.md#jti)
- [nbf](Resolution.md#nbf)
- [resolution](Resolution.md#resolution)
- [sub](Resolution.md#sub)
- [type](Resolution.md#type)

## Properties

### aud

• `Optional` **aud**: `string` \| `string`[]

#### Inherited from

JWTPayload.aud

#### Defined in

node_modules/jose/dist/types/types.d.ts:215

___

### dataExchangeId

• **dataExchangeId**: `string`

#### Defined in

[src/ts/types.ts:147](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe11e28/src/ts/types.ts#L147)

___

### exp

• `Optional` **exp**: `number`

#### Inherited from

JWTPayload.exp

#### Defined in

node_modules/jose/dist/types/types.d.ts:218

___

### iat

• **iat**: `number`

#### Overrides

JWTPayload.iat

#### Defined in

[src/ts/types.ts:148](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe11e28/src/ts/types.ts#L148)

___

### iss

• **iss**: `string`

#### Overrides

JWTPayload.iss

#### Defined in

[src/ts/types.ts:149](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe11e28/src/ts/types.ts#L149)

___

### jti

• `Optional` **jti**: `string`

#### Inherited from

JWTPayload.jti

#### Defined in

node_modules/jose/dist/types/types.d.ts:216

___

### nbf

• `Optional` **nbf**: `number`

#### Inherited from

JWTPayload.nbf

#### Defined in

node_modules/jose/dist/types/types.d.ts:217

___

### resolution

• `Optional` **resolution**: `string`

#### Defined in

[src/ts/types.ts:146](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe11e28/src/ts/types.ts#L146)

___

### sub

• `Optional` **sub**: `string`

#### Inherited from

JWTPayload.sub

#### Defined in

node_modules/jose/dist/types/types.d.ts:214

___

### type

• `Optional` **type**: `string`

#### Defined in

[src/ts/types.ts:145](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe11e28/src/ts/types.ts#L145)
