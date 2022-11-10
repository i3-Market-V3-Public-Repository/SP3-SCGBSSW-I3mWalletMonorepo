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

[src/ts/types.ts:137](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/d2ad01f/src/ts/types.ts#L137)

___

### iat

• **iat**: `number`

#### Overrides

[ProofPayload](ProofPayload.md).[iat](ProofPayload.md#iat)

#### Defined in

[src/ts/types.ts:135](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/d2ad01f/src/ts/types.ts#L135)

___

### iss

• **iss**: ``"orig"`` \| ``"dest"``

#### Overrides

[ProofPayload](ProofPayload.md).[iss](ProofPayload.md#iss)

#### Defined in

[src/ts/types.ts:134](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/d2ad01f/src/ts/types.ts#L134)

___

### por

• **por**: `string`

#### Defined in

[src/ts/types.ts:136](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/d2ad01f/src/ts/types.ts#L136)

___

### proofType

• **proofType**: ``"request"``

#### Overrides

[ProofPayload](ProofPayload.md).[proofType](ProofPayload.md#prooftype)

#### Defined in

[src/ts/types.ts:133](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/d2ad01f/src/ts/types.ts#L133)
