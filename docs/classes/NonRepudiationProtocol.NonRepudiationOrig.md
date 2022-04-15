# Class: NonRepudiationOrig

[NonRepudiationProtocol](../modules/NonRepudiationProtocol.md).NonRepudiationOrig

The base class that should be instantiated by the origin of a data
exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
likely to be a Provider.

## Table of contents

### Constructors

- [constructor](NonRepudiationProtocol.NonRepudiationOrig.md#constructor)

### Properties

- [agreement](NonRepudiationProtocol.NonRepudiationOrig.md#agreement)
- [block](NonRepudiationProtocol.NonRepudiationOrig.md#block)
- [dltAgent](NonRepudiationProtocol.NonRepudiationOrig.md#dltagent)
- [exchange](NonRepudiationProtocol.NonRepudiationOrig.md#exchange)
- [initialized](NonRepudiationProtocol.NonRepudiationOrig.md#initialized)
- [jwkPairOrig](NonRepudiationProtocol.NonRepudiationOrig.md#jwkpairorig)
- [publicJwkDest](NonRepudiationProtocol.NonRepudiationOrig.md#publicjwkdest)

### Methods

- [generatePoO](NonRepudiationProtocol.NonRepudiationOrig.md#generatepoo)
- [generatePoP](NonRepudiationProtocol.NonRepudiationOrig.md#generatepop)
- [generateVerificationRequest](NonRepudiationProtocol.NonRepudiationOrig.md#generateverificationrequest)
- [verifyPoR](NonRepudiationProtocol.NonRepudiationOrig.md#verifypor)

## Constructors

### constructor

• **new NonRepudiationOrig**(`agreement`, `privateJwk`, `block`, `dltAgent`)

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `agreement` | [`DataExchangeAgreement`](../interfaces/DataExchangeAgreement.md) | a DataExchangeAgreement |
| `privateJwk` | [`JWK`](../interfaces/JWK.md) | the private key that will be used to sign the proofs |
| `block` | `Uint8Array` | the block of data to transmit in this data exchange |
| `dltAgent` | [`NrpDltAgentOrig`](../interfaces/Signers.NrpDltAgentOrig.md) | a DLT agent providing read-write connection to NRP smart contract |

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:31](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe6e4da/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L31)

## Properties

### agreement

• **agreement**: [`DataExchangeAgreement`](../interfaces/DataExchangeAgreement.md)

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:17](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe6e4da/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L17)

___

### block

• **block**: [`OrigBlock`](../interfaces/OrigBlock.md)

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:21](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe6e4da/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L21)

___

### dltAgent

• **dltAgent**: [`NrpDltAgentOrig`](../interfaces/Signers.NrpDltAgentOrig.md)

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe6e4da/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L22)

___

### exchange

• **exchange**: [`DataExchange`](../interfaces/DataExchange.md)

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:18](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe6e4da/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L18)

___

### initialized

• `Readonly` **initialized**: `Promise`<`boolean`\>

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:23](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe6e4da/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L23)

___

### jwkPairOrig

• **jwkPairOrig**: [`JwkPair`](../interfaces/JwkPair.md)

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:19](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe6e4da/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L19)

___

### publicJwkDest

• **publicJwkDest**: [`JWK`](../interfaces/JWK.md)

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:20](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe6e4da/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L20)

## Methods

### generatePoO

▸ **generatePoO**(): `Promise`<[`StoredProof`](../interfaces/StoredProof.md)<[`PoOPayload`](../interfaces/PoOPayload.md)\>\>

Creates the proof of origin (PoO).
Besides returning its value, it is also stored in this.block.poo

#### Returns

`Promise`<[`StoredProof`](../interfaces/StoredProof.md)<[`PoOPayload`](../interfaces/PoOPayload.md)\>\>

a compact JWS with the PoO along with its decoded payload

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:106](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe6e4da/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L106)

___

### generatePoP

▸ **generatePoP**(): `Promise`<[`StoredProof`](../interfaces/StoredProof.md)<[`PoPPayload`](../interfaces/PoPPayload.md)\>\>

Creates the proof of publication (PoP).
Besides returning its value, it is also stored in `this.block.pop`

#### Returns

`Promise`<[`StoredProof`](../interfaces/StoredProof.md)<[`PoPPayload`](../interfaces/PoPPayload.md)\>\>

a compact JWS with the PoP

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:162](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe6e4da/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L162)

___

### generateVerificationRequest

▸ **generateVerificationRequest**(): `Promise`<`string`\>

Generates a verification request that can be used to query the
Conflict-Resolver Service for completeness of the non-repudiation protocol

#### Returns

`Promise`<`string`\>

the verification request as a compact JWS signed with 'orig's private key

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:189](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe6e4da/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L189)

___

### verifyPoR

▸ **verifyPoR**(`por`, `options?`): `Promise`<[`StoredProof`](../interfaces/StoredProof.md)<[`PoRPayload`](../interfaces/PoRPayload.md)\>\>

Verifies a proof of reception.
If verification passes, `por` is added to `this.block`

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `por` | `string` | A PoR in caompact JWS format |
| `options?` | `Pick`<[`TimestampVerifyOptions`](../interfaces/TimestampVerifyOptions.md), ``"timestamp"`` \| ``"tolerance"``\> | time-related verifications |

#### Returns

`Promise`<[`StoredProof`](../interfaces/StoredProof.md)<[`PoRPayload`](../interfaces/PoRPayload.md)\>\>

the verified payload and protected header

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:125](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe6e4da/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L125)
