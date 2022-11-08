# Class: ConflictResolver

[ConflictResolution](../modules/ConflictResolution.md).ConflictResolver

The base class that should be instantiated in order to create a Conflict Resolver instance.
The Conflict Resolver is an external entity that can:
 1. verify the completeness of a data exchange that used the non-repudiation protocol;
 2. resolve a dispute when a consumer states that she/he cannot decrypt the data received

## Table of contents

### Constructors

- [constructor](ConflictResolution.ConflictResolver.md#constructor)

### Properties

- [dltAgent](ConflictResolution.ConflictResolver.md#dltagent)
- [jwkPair](ConflictResolution.ConflictResolver.md#jwkpair)

### Methods

- [resolveCompleteness](ConflictResolution.ConflictResolver.md#resolvecompleteness)
- [resolveDispute](ConflictResolution.ConflictResolver.md#resolvedispute)

## Constructors

### constructor

• **new ConflictResolver**(`jwkPair`, `dltAgent`)

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `jwkPair` | [`JwkPair`](../interfaces/JwkPair.md) | a pair of public/private keys in JWK format |
| `dltAgent` | [`NrpDltAgentDest`](../interfaces/Signers.NrpDltAgentDest.md) | a DLT agent providing read-only access to the non-repudiation protocol smart contract |

#### Defined in

[src/ts/conflict-resolution/ConflictResolver.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/04fcfd0/src/ts/conflict-resolution/ConflictResolver.ts#L26)

## Properties

### dltAgent

• **dltAgent**: [`NrpDltAgentDest`](../interfaces/Signers.NrpDltAgentDest.md)

#### Defined in

[src/ts/conflict-resolution/ConflictResolver.ts:18](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/04fcfd0/src/ts/conflict-resolution/ConflictResolver.ts#L18)

___

### jwkPair

• **jwkPair**: [`JwkPair`](../interfaces/JwkPair.md)

#### Defined in

[src/ts/conflict-resolution/ConflictResolver.ts:17](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/04fcfd0/src/ts/conflict-resolution/ConflictResolver.ts#L17)

## Methods

### resolveCompleteness

▸ **resolveCompleteness**(`verificationRequest`): `Promise`<`string`\>

Checks if a give data exchange has completed succesfully

#### Parameters

| Name | Type |
| :------ | :------ |
| `verificationRequest` | `string` |

#### Returns

`Promise`<`string`\>

a signed resolution

#### Defined in

[src/ts/conflict-resolution/ConflictResolver.ts:52](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/04fcfd0/src/ts/conflict-resolution/ConflictResolver.ts#L52)

___

### resolveDispute

▸ **resolveDispute**(`disputeRequest`): `Promise`<`string`\>

Checks if the cipherblock provided in a data exchange can be decrypted
with the published secret.

**`Todo`**

Check also data schema

#### Parameters

| Name | Type |
| :------ | :------ |
| `disputeRequest` | `string` |

#### Returns

`Promise`<`string`\>

a signed resolution

#### Defined in

[src/ts/conflict-resolution/ConflictResolver.ts:98](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/04fcfd0/src/ts/conflict-resolution/ConflictResolver.ts#L98)
