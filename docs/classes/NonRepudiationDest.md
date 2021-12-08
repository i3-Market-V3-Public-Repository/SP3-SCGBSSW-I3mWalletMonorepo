# Class: NonRepudiationDest

The base class that should be instantiated by the destination of a data
exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
likely to be a Consumer.

## Table of contents

### Constructors

- [constructor](NonRepudiationDest.md#constructor)

### Properties

- [agreement](NonRepudiationDest.md#agreement)
- [block](NonRepudiationDest.md#block)
- [dltConfig](NonRepudiationDest.md#dltconfig)
- [dltContract](NonRepudiationDest.md#dltcontract)
- [exchange](NonRepudiationDest.md#exchange)
- [initialized](NonRepudiationDest.md#initialized)
- [jwkPairDest](NonRepudiationDest.md#jwkpairdest)
- [publicJwkOrig](NonRepudiationDest.md#publicjwkorig)

### Methods

- [\_dltSetup](NonRepudiationDest.md#_dltsetup)
- [decrypt](NonRepudiationDest.md#decrypt)
- [generatePoR](NonRepudiationDest.md#generatepor)
- [getSecretFromLedger](NonRepudiationDest.md#getsecretfromledger)
- [init](NonRepudiationDest.md#init)
- [verifyPoO](NonRepudiationDest.md#verifypoo)
- [verifyPoP](NonRepudiationDest.md#verifypop)

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

[src/ts/NonRepudiationDest.ts:37](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/a77470d/src/ts/NonRepudiationDest.ts#L37)

## Properties

### agreement

• **agreement**: [`DataExchangeAgreement`](../interfaces/DataExchangeAgreement.md)

#### Defined in

[src/ts/NonRepudiationDest.ts:23](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/a77470d/src/ts/NonRepudiationDest.ts#L23)

___

### block

• **block**: [`Block`](../interfaces/Block.md)

#### Defined in

[src/ts/NonRepudiationDest.ts:27](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/a77470d/src/ts/NonRepudiationDest.ts#L27)

___

### dltConfig

• **dltConfig**: [`DltConfig`](../interfaces/DltConfig.md)

#### Defined in

[src/ts/NonRepudiationDest.ts:28](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/a77470d/src/ts/NonRepudiationDest.ts#L28)

___

### dltContract

• **dltContract**: `Contract`

#### Defined in

[src/ts/NonRepudiationDest.ts:29](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/a77470d/src/ts/NonRepudiationDest.ts#L29)

___

### exchange

• `Optional` **exchange**: [`DataExchange`](../interfaces/DataExchange.md)

#### Defined in

[src/ts/NonRepudiationDest.ts:24](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/a77470d/src/ts/NonRepudiationDest.ts#L24)

___

### initialized

• **initialized**: `Promise`<`boolean`\>

#### Defined in

[src/ts/NonRepudiationDest.ts:30](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/a77470d/src/ts/NonRepudiationDest.ts#L30)

___

### jwkPairDest

• **jwkPairDest**: [`JwkPair`](../interfaces/JwkPair.md)

#### Defined in

[src/ts/NonRepudiationDest.ts:25](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/a77470d/src/ts/NonRepudiationDest.ts#L25)

___

### publicJwkOrig

• **publicJwkOrig**: [`JWK`](../interfaces/JWK.md)

#### Defined in

[src/ts/NonRepudiationDest.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/a77470d/src/ts/NonRepudiationDest.ts#L26)

## Methods

### \_dltSetup

▸ `Private` **_dltSetup**(): `void`

#### Returns

`void`

#### Defined in

[src/ts/NonRepudiationDest.ts:67](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/a77470d/src/ts/NonRepudiationDest.ts#L67)

___

### decrypt

▸ **decrypt**(): `Promise`<`Uint8Array`\>

Decrypts the cipherblock once all the previous proofs have been verified

**`throws`** Error if the previous proofs have not been verified or the decrypted block does not meet the committed one

#### Returns

`Promise`<`Uint8Array`\>

the decrypted block

#### Defined in

[src/ts/NonRepudiationDest.ts:261](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/a77470d/src/ts/NonRepudiationDest.ts#L261)

___

### generatePoR

▸ **generatePoR**(): `Promise`<[`StoredProof`](../interfaces/StoredProof.md)\>

Creates the proof of reception (PoR).
Besides returning its value, it is also stored in `this.block.por`

#### Returns

`Promise`<[`StoredProof`](../interfaces/StoredProof.md)\>

the PoR as a compact JWS along with its decoded payload

#### Defined in

[src/ts/NonRepudiationDest.ts:141](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/a77470d/src/ts/NonRepudiationDest.ts#L141)

___

### getSecretFromLedger

▸ **getSecretFromLedger**(): `Promise`<{ `hex`: `string` ; `jwk`: [`JWK`](../interfaces/JWK.md)  }\>

Just in case the PoP is not received, the secret can be downloaded from the ledger.
The secret should be downloaded before poo.iat + pooTopop max delay.

#### Returns

`Promise`<{ `hex`: `string` ; `jwk`: [`JWK`](../interfaces/JWK.md)  }\>

the secret

#### Defined in

[src/ts/NonRepudiationDest.ts:214](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/a77470d/src/ts/NonRepudiationDest.ts#L214)

___

### init

▸ **init**(): `Promise`<`void`\>

Initialize this instance. It MUST be invoked before calling any other method.

#### Returns

`Promise`<`void`\>

#### Defined in

[src/ts/NonRepudiationDest.ts:82](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/a77470d/src/ts/NonRepudiationDest.ts#L82)

___

### verifyPoO

▸ **verifyPoO**(`poo`, `cipherblock`, `clockToleranceMs?`, `currentDate?`): `Promise`<[`JWTVerifyResult`](../interfaces/JWTVerifyResult.md)\>

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

`Promise`<[`JWTVerifyResult`](../interfaces/JWTVerifyResult.md)\>

the verified payload and protected header

#### Defined in

[src/ts/NonRepudiationDest.ts:97](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/a77470d/src/ts/NonRepudiationDest.ts#L97)

___

### verifyPoP

▸ **verifyPoP**(`pop`, `clockToleranceMs?`, `currentDate?`): `Promise`<[`JWTVerifyResult`](../interfaces/JWTVerifyResult.md)\>

Verifies a received Proof of Publication (PoP) and returns the secret

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `pop` | `string` | a PoP in compact JWS |
| `clockToleranceMs?` | `number` | expected clock tolerance in milliseconds when comparing Dates |
| `currentDate?` | `Date` | check the proof as it were checked in this date |

#### Returns

`Promise`<[`JWTVerifyResult`](../interfaces/JWTVerifyResult.md)\>

the verified payload (that includes the secret that can be used to decrypt the cipherblock) and protected header

#### Defined in

[src/ts/NonRepudiationDest.ts:167](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/a77470d/src/ts/NonRepudiationDest.ts#L167)
