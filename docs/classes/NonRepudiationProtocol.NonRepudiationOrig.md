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
- [dltConfig](NonRepudiationProtocol.NonRepudiationOrig.md#dltconfig)
- [dltContract](NonRepudiationProtocol.NonRepudiationOrig.md#dltcontract)
- [exchange](NonRepudiationProtocol.NonRepudiationOrig.md#exchange)
- [jwkPairOrig](NonRepudiationProtocol.NonRepudiationOrig.md#jwkpairorig)
- [publicJwkDest](NonRepudiationProtocol.NonRepudiationOrig.md#publicjwkdest)

### Methods

- [generatePoO](NonRepudiationProtocol.NonRepudiationOrig.md#generatepoo)
- [generatePoP](NonRepudiationProtocol.NonRepudiationOrig.md#generatepop)
- [generateVerificationRequest](NonRepudiationProtocol.NonRepudiationOrig.md#generateverificationrequest)
- [verifyPoR](NonRepudiationProtocol.NonRepudiationOrig.md#verifypor)

## Constructors

### constructor

• **new NonRepudiationOrig**(`agreement`, `privateJwk`, `block`, `dltConfig?`, `privateLedgerKeyHex?`)

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `agreement` | [`DataExchangeAgreement`](../interfaces/DataExchangeAgreement.md) | a DataExchangeAgreement |
| `privateJwk` | [`JWK`](../interfaces/JWK.md) | the private key that will be used to sign the proofs |
| `block` | `Uint8Array` | the block of data to transmit in this data exchange |
| `dltConfig?` | `Partial`<[`DltConfig`](../interfaces/DltConfig.md)\> | an object with the necessary configuration for the (Ethereum-like) DLT |
| `privateLedgerKeyHex?` | `string` | the private key (d parameter) as a hexadecimal string used to sign transactions to the ledger. If not provided, it is assumed that a DltSigner is provided in the dltConfig |

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:35](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee76e40/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L35)

## Properties

### agreement

• **agreement**: [`DataExchangeAgreement`](../interfaces/DataExchangeAgreement.md)

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:19](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee76e40/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L19)

___

### block

• **block**: [`OrigBlock`](../interfaces/OrigBlock.md)

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:23](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee76e40/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L23)

___

### dltConfig

• **dltConfig**: `Required`<[`DltConfig`](../interfaces/DltConfig.md)\>

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:24](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee76e40/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L24)

___

### dltContract

• **dltContract**: `Contract`

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:25](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee76e40/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L25)

___

### exchange

• **exchange**: [`DataExchange`](../interfaces/DataExchange.md)

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:20](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee76e40/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L20)

___

### jwkPairOrig

• **jwkPairOrig**: [`JwkPair`](../interfaces/JwkPair.md)

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:21](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee76e40/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L21)

___

### publicJwkDest

• **publicJwkDest**: [`JWK`](../interfaces/JWK.md)

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee76e40/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L22)

## Methods

### generatePoO

▸ **generatePoO**(): `Promise`<[`StoredProof`](../interfaces/StoredProof.md)<[`PoOPayload`](../interfaces/PoOPayload.md)\>\>

Creates the proof of origin (PoO).
Besides returning its value, it is also stored in this.block.poo

#### Returns

`Promise`<[`StoredProof`](../interfaces/StoredProof.md)<[`PoOPayload`](../interfaces/PoOPayload.md)\>\>

a compact JWS with the PoO along with its decoded payload

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:130](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee76e40/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L130)

___

### generatePoP

▸ **generatePoP**(): `Promise`<[`StoredProof`](../interfaces/StoredProof.md)<[`PoPPayload`](../interfaces/PoPPayload.md)\>\>

Creates the proof of publication (PoP).
Besides returning its value, it is also stored in `this.block.pop`

#### Returns

`Promise`<[`StoredProof`](../interfaces/StoredProof.md)<[`PoPPayload`](../interfaces/PoPPayload.md)\>\>

a compact JWS with the PoP

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:186](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee76e40/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L186)

___

### generateVerificationRequest

▸ **generateVerificationRequest**(): `Promise`<`string`\>

Generates a verification request that can be used to query the
Conflict-Resolver Service for completeness of the non-repudiation protocol

#### Returns

`Promise`<`string`\>

the verification request as a compact JWS signed with 'orig's private key

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:234](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee76e40/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L234)

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

[src/ts/non-repudiation-protocol/NonRepudiationOrig.ts:149](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee76e40/src/ts/non-repudiation-protocol/NonRepudiationOrig.ts#L149)
