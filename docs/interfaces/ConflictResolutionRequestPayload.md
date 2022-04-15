# Interface: ConflictResolutionRequestPayload

## Hierarchy

- [`ProofPayload`](ProofPayload.md)

  ↳ **`ConflictResolutionRequestPayload`**

  ↳↳ [`VerificationRequestPayload`](VerificationRequestPayload.md)

  ↳↳ [`DisputeRequestPayload`](DisputeRequestPayload.md)

## Table of contents

### Properties

- [dataExchangeId](ConflictResolutionRequestPayload.md#dataexchangeid)
- [iat](ConflictResolutionRequestPayload.md#iat)
- [iss](ConflictResolutionRequestPayload.md#iss)
- [por](ConflictResolutionRequestPayload.md#por)
- [proofType](ConflictResolutionRequestPayload.md#prooftype)

## Properties

### dataExchangeId

• **dataExchangeId**: `string`

#### Defined in

[src/ts/types.ts:130](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe6e4da/src/ts/types.ts#L130)

___

### iat

• **iat**: `number`

#### Overrides

[ProofPayload](ProofPayload.md).[iat](ProofPayload.md#iat)

#### Defined in

[src/ts/types.ts:128](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe6e4da/src/ts/types.ts#L128)

___

### iss

• **iss**: ``"orig"`` \| ``"dest"``

#### Overrides

[ProofPayload](ProofPayload.md).[iss](ProofPayload.md#iss)

#### Defined in

[src/ts/types.ts:127](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe6e4da/src/ts/types.ts#L127)

___

### por

• **por**: `string`

#### Defined in

[src/ts/types.ts:129](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe6e4da/src/ts/types.ts#L129)

___

### proofType

• **proofType**: ``"request"``

#### Overrides

[ProofPayload](ProofPayload.md).[proofType](ProofPayload.md#prooftype)

#### Defined in

[src/ts/types.ts:126](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe6e4da/src/ts/types.ts#L126)
