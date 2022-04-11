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

- [jwkPair](ConflictResolution.ConflictResolver.md#jwkpair)
- [wallet](ConflictResolution.ConflictResolver.md#wallet)

### Methods

- [resolveCompleteness](ConflictResolution.ConflictResolver.md#resolvecompleteness)
- [resolveDispute](ConflictResolution.ConflictResolver.md#resolvedispute)

## Constructors

### constructor

• **new ConflictResolver**(`jwkPair`, `walletAgent?`)

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `jwkPair` | [`JwkPair`](../interfaces/JwkPair.md) | a pair of public/private keys in JWK format |
| `walletAgent?` | [`WalletAgentDest`](../interfaces/Signers.WalletAgentDest.md) | a wallet agent providing read-only access to the non-repudiation protocol smart contract |

#### Defined in

[src/ts/conflict-resolution/ConflictResolver.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/b64ca83/src/ts/conflict-resolution/ConflictResolver.ts#L26)

## Properties

### jwkPair

• **jwkPair**: [`JwkPair`](../interfaces/JwkPair.md)

#### Defined in

[src/ts/conflict-resolution/ConflictResolver.ts:17](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/b64ca83/src/ts/conflict-resolution/ConflictResolver.ts#L17)

___

### wallet

• **wallet**: [`WalletAgentDest`](../interfaces/Signers.WalletAgentDest.md)

#### Defined in

[src/ts/conflict-resolution/ConflictResolver.ts:18](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/b64ca83/src/ts/conflict-resolution/ConflictResolver.ts#L18)

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

[src/ts/conflict-resolution/ConflictResolver.ts:57](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/b64ca83/src/ts/conflict-resolution/ConflictResolver.ts#L57)

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

[src/ts/conflict-resolution/ConflictResolver.ts:103](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/b64ca83/src/ts/conflict-resolution/ConflictResolver.ts#L103)
