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

- [dltConfig](ConflictResolution.ConflictResolver.md#dltconfig)
- [dltContract](ConflictResolution.ConflictResolver.md#dltcontract)
- [jwkPair](ConflictResolution.ConflictResolver.md#jwkpair)

### Methods

- [resolveCompleteness](ConflictResolution.ConflictResolver.md#resolvecompleteness)
- [resolveDispute](ConflictResolution.ConflictResolver.md#resolvedispute)

## Constructors

### constructor

• **new ConflictResolver**(`jwkPair`, `dltConfig?`)

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `jwkPair` | [`JwkPair`](../interfaces/JwkPair.md) | a pair of public/private keys in JWK format |
| `dltConfig?` | `Partial`<[`DltConfig`](../interfaces/DltConfig.md)\> |  |

#### Defined in

[src/ts/conflict-resolution/ConflictResolver.ts:28](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/1e88c9a/src/ts/conflict-resolution/ConflictResolver.ts#L28)

## Properties

### dltConfig

• **dltConfig**: [`DltConfig`](../interfaces/DltConfig.md)

#### Defined in

[src/ts/conflict-resolution/ConflictResolver.ts:19](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/1e88c9a/src/ts/conflict-resolution/ConflictResolver.ts#L19)

___

### dltContract

• **dltContract**: `Contract`

#### Defined in

[src/ts/conflict-resolution/ConflictResolver.ts:20](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/1e88c9a/src/ts/conflict-resolution/ConflictResolver.ts#L20)

___

### jwkPair

• **jwkPair**: [`JwkPair`](../interfaces/JwkPair.md)

#### Defined in

[src/ts/conflict-resolution/ConflictResolver.ts:18](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/1e88c9a/src/ts/conflict-resolution/ConflictResolver.ts#L18)

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

[src/ts/conflict-resolution/ConflictResolver.ts:68](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/1e88c9a/src/ts/conflict-resolution/ConflictResolver.ts#L68)

___

### resolveDispute

▸ **resolveDispute**(`disputeRequest`): `Promise`<`string`\>

Checks if the cipherblock provided in a data exchange can be decrypted
with the published secret.

**`todo`** Check also data schema

#### Parameters

| Name | Type |
| :------ | :------ |
| `disputeRequest` | `string` |

#### Returns

`Promise`<`string`\>

a signed resolution

#### Defined in

[src/ts/conflict-resolution/ConflictResolver.ts:114](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/1e88c9a/src/ts/conflict-resolution/ConflictResolver.ts#L114)
