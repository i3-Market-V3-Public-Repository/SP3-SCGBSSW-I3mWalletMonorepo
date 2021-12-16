# Class: NonRepudiationDest

[NonRepudiationProtocol](../modules/NonRepudiationProtocol.md).NonRepudiationDest

The base class that should be instantiated by the destination of a data
exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
likely to be a Consumer.

## Table of contents

### Constructors

- [constructor](NonRepudiationProtocol.NonRepudiationDest.md#constructor)

### Properties

- [agreement](NonRepudiationProtocol.NonRepudiationDest.md#agreement)
- [block](NonRepudiationProtocol.NonRepudiationDest.md#block)
- [dltConfig](NonRepudiationProtocol.NonRepudiationDest.md#dltconfig)
- [dltContract](NonRepudiationProtocol.NonRepudiationDest.md#dltcontract)
- [exchange](NonRepudiationProtocol.NonRepudiationDest.md#exchange)
- [jwkPairDest](NonRepudiationProtocol.NonRepudiationDest.md#jwkpairdest)
- [publicJwkOrig](NonRepudiationProtocol.NonRepudiationDest.md#publicjwkorig)

### Methods

- [decrypt](NonRepudiationProtocol.NonRepudiationDest.md#decrypt)
- [generateDisputeRequest](NonRepudiationProtocol.NonRepudiationDest.md#generatedisputerequest)
- [generatePoR](NonRepudiationProtocol.NonRepudiationDest.md#generatepor)
- [generateVerificationRequest](NonRepudiationProtocol.NonRepudiationDest.md#generateverificationrequest)
- [getSecretFromLedger](NonRepudiationProtocol.NonRepudiationDest.md#getsecretfromledger)
- [verifyPoO](NonRepudiationProtocol.NonRepudiationDest.md#verifypoo)
- [verifyPoP](NonRepudiationProtocol.NonRepudiationDest.md#verifypop)

## Constructors

### constructor

• **new NonRepudiationDest**(`agreement`, `privateJwk`, `dltConfig?`)

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `agreement` | [`DataExchangeAgreement`](../interfaces/DataExchangeAgreement.md) | a DataExchangeAgreement |
| `privateJwk` | [`JWK`](../interfaces/JWK.md) | the private key that will be used to sign the proofs |
| `dltConfig?` | `Partial`<[`DltConfig`](../interfaces/DltConfig.md)\> | an object with the necessary configuration for the (Ethereum-like) DLT |

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationDest.ts:35](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe11e28/src/ts/non-repudiation-protocol/NonRepudiationDest.ts#L35)

## Properties

### agreement

• **agreement**: [`DataExchangeAgreement`](../interfaces/DataExchangeAgreement.md)

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationDest.ts:21](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe11e28/src/ts/non-repudiation-protocol/NonRepudiationDest.ts#L21)

___

### block

• **block**: [`Block`](../interfaces/Block.md)

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationDest.ts:25](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe11e28/src/ts/non-repudiation-protocol/NonRepudiationDest.ts#L25)

___

### dltConfig

• **dltConfig**: [`DltConfig`](../interfaces/DltConfig.md)

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationDest.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe11e28/src/ts/non-repudiation-protocol/NonRepudiationDest.ts#L26)

___

### dltContract

• **dltContract**: `Contract`

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationDest.ts:27](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe11e28/src/ts/non-repudiation-protocol/NonRepudiationDest.ts#L27)

___

### exchange

• `Optional` **exchange**: [`DataExchange`](../interfaces/DataExchange.md)

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationDest.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe11e28/src/ts/non-repudiation-protocol/NonRepudiationDest.ts#L22)

___

### jwkPairDest

• **jwkPairDest**: [`JwkPair`](../interfaces/JwkPair.md)

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationDest.ts:23](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe11e28/src/ts/non-repudiation-protocol/NonRepudiationDest.ts#L23)

___

### publicJwkOrig

• **publicJwkOrig**: [`JWK`](../interfaces/JWK.md)

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationDest.ts:24](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe11e28/src/ts/non-repudiation-protocol/NonRepudiationDest.ts#L24)

## Methods

### decrypt

▸ **decrypt**(): `Promise`<`Uint8Array`\>

Decrypts the cipherblock once all the previous proofs have been verified

#### Returns

`Promise`<`Uint8Array`\>

the decrypted block

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationDest.ts:245](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe11e28/src/ts/non-repudiation-protocol/NonRepudiationDest.ts#L245)

___

### generateDisputeRequest

▸ **generateDisputeRequest**(): `Promise`<`string`\>

Generates a dispute request that can be used to query the
Conflict-Resolver Service regarding impossibility to decrypt the cipherblock with the received secret

#### Returns

`Promise`<`string`\>

the dispute request as a compact JWS signed with 'dest's private key

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationDest.ts:290](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe11e28/src/ts/non-repudiation-protocol/NonRepudiationDest.ts#L290)

___

### generatePoR

▸ **generatePoR**(): `Promise`<[`StoredProof`](../interfaces/StoredProof.md)<[`PoRPayload`](../interfaces/PoRPayload.md)\>\>

Creates the proof of reception (PoR).
Besides returning its value, it is also stored in `this.block.por`

#### Returns

`Promise`<[`StoredProof`](../interfaces/StoredProof.md)<[`PoRPayload`](../interfaces/PoRPayload.md)\>\>

the PoR as a compact JWS along with its decoded payload

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationDest.ts:139](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe11e28/src/ts/non-repudiation-protocol/NonRepudiationDest.ts#L139)

___

### generateVerificationRequest

▸ **generateVerificationRequest**(): `Promise`<`string`\>

Generates a verification request that can be used to query the
Conflict-Resolver Service for completeness of the non-repudiation protocol

#### Returns

`Promise`<`string`\>

the verification request as a compact JWS signed with 'dest's private key

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationDest.ts:274](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe11e28/src/ts/non-repudiation-protocol/NonRepudiationDest.ts#L274)

___

### getSecretFromLedger

▸ **getSecretFromLedger**(): `Promise`<{ `hex`: `string` ; `jwk`: [`JWK`](../interfaces/JWK.md)  }\>

Just in case the PoP is not received, the secret can be downloaded from the ledger.
The secret should be downloaded before poo.iat + pooToPop max delay.

#### Returns

`Promise`<{ `hex`: `string` ; `jwk`: [`JWK`](../interfaces/JWK.md)  }\>

the secret

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationDest.ts:212](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe11e28/src/ts/non-repudiation-protocol/NonRepudiationDest.ts#L212)

___

### verifyPoO

▸ **verifyPoO**(`poo`, `cipherblock`, `clockToleranceMs?`, `currentDate?`): `Promise`<[`JwsHeaderAndPayload`](../interfaces/JwsHeaderAndPayload.md)<[`PoOPayload`](../interfaces/PoOPayload.md)\>\>

Verifies a proof of origin against the received cipherblock.
If verification passes, `pop` and `cipherblock` are added to this.block

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `poo` | `string` | a Proof of Origin (PoO) in compact JWS format |
| `cipherblock` | `string` | a cipherblock as a JWE |
| `clockToleranceMs?` | `number` | expected clock tolerance in milliseconds when comparing Dates |
| `currentDate?` | `Date` | check the PoO as it were checked in this date |

#### Returns

`Promise`<[`JwsHeaderAndPayload`](../interfaces/JwsHeaderAndPayload.md)<[`PoOPayload`](../interfaces/PoOPayload.md)\>\>

the verified payload and protected header

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationDest.ts:89](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe11e28/src/ts/non-repudiation-protocol/NonRepudiationDest.ts#L89)

___

### verifyPoP

▸ **verifyPoP**(`pop`, `clockToleranceMs?`, `currentDate?`): `Promise`<[`JwsHeaderAndPayload`](../interfaces/JwsHeaderAndPayload.md)<[`PoPPayload`](../interfaces/PoPPayload.md)\>\>

Verifies a received Proof of Publication (PoP) and returns the secret

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `pop` | `string` | a PoP in compact JWS |
| `clockToleranceMs?` | `number` | expected clock tolerance in milliseconds when comparing Dates |
| `currentDate?` | `Date` | check the proof as it were checked in this date |

#### Returns

`Promise`<[`JwsHeaderAndPayload`](../interfaces/JwsHeaderAndPayload.md)<[`PoPPayload`](../interfaces/PoPPayload.md)\>\>

the verified payload (that includes the secret that can be used to decrypt the cipherblock) and protected header

#### Defined in

[src/ts/non-repudiation-protocol/NonRepudiationDest.ts:165](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/fe11e28/src/ts/non-repudiation-protocol/NonRepudiationDest.ts#L165)
