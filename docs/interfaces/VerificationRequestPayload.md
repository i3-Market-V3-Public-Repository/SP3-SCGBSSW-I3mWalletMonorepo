# Interface: VerificationRequestPayload

## Hierarchy

- `ConflictResolutionRequest`

  ↳ **`VerificationRequestPayload`**

## Table of contents

### Properties

- [aud](VerificationRequestPayload.md#aud)
- [dataExchangeId](VerificationRequestPayload.md#dataexchangeid)
- [exp](VerificationRequestPayload.md#exp)
- [iat](VerificationRequestPayload.md#iat)
- [iss](VerificationRequestPayload.md#iss)
- [jti](VerificationRequestPayload.md#jti)
- [nbf](VerificationRequestPayload.md#nbf)
- [por](VerificationRequestPayload.md#por)
- [sub](VerificationRequestPayload.md#sub)
- [type](VerificationRequestPayload.md#type)

## Properties

### aud

• `Optional` **aud**: `string` \| `string`[]

#### Inherited from

ConflictResolutionRequest.aud

#### Defined in

node_modules/jose/dist/types/types.d.ts:215

___

### dataExchangeId

• **dataExchangeId**: `string`

#### Inherited from

ConflictResolutionRequest.dataExchangeId

#### Defined in

[src/ts/types.ts:130](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/f58faf3/src/ts/types.ts#L130)

___

### exp

• `Optional` **exp**: `number`

#### Inherited from

ConflictResolutionRequest.exp

#### Defined in

node_modules/jose/dist/types/types.d.ts:218

___

### iat

• **iat**: `number`

#### Inherited from

ConflictResolutionRequest.iat

#### Defined in

[src/ts/types.ts:128](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/f58faf3/src/ts/types.ts#L128)

___

### iss

• **iss**: ``"orig"`` \| ``"dest"``

#### Inherited from

ConflictResolutionRequest.iss

#### Defined in

[src/ts/types.ts:127](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/f58faf3/src/ts/types.ts#L127)

___

### jti

• `Optional` **jti**: `string`

#### Inherited from

ConflictResolutionRequest.jti

#### Defined in

node_modules/jose/dist/types/types.d.ts:216

___

### nbf

• `Optional` **nbf**: `number`

#### Inherited from

ConflictResolutionRequest.nbf

#### Defined in

node_modules/jose/dist/types/types.d.ts:217

___

### por

• **por**: `string`

#### Inherited from

ConflictResolutionRequest.por

#### Defined in

[src/ts/types.ts:129](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/f58faf3/src/ts/types.ts#L129)

___

### sub

• `Optional` **sub**: `string`

#### Inherited from

ConflictResolutionRequest.sub

#### Defined in

node_modules/jose/dist/types/types.d.ts:214

___

### type

• **type**: ``"verificationRequest"``

#### Defined in

[src/ts/types.ts:134](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/f58faf3/src/ts/types.ts#L134)
