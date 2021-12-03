# Class: NonRepudiationDest

The base class that should be instantiated by the destination of a data
exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
likely to be a Consumer.

## Table of contents

### Constructors

- [constructor](NonRepudiationDest.md#constructor)

### Properties

- [block](NonRepudiationDest.md#block)
- [checked](NonRepudiationDest.md#checked)
- [exchange](NonRepudiationDest.md#exchange)
- [jwkPairDest](NonRepudiationDest.md#jwkpairdest)
- [publicJwkOrig](NonRepudiationDest.md#publicjwkorig)

### Methods

- [\_checkInit](NonRepudiationDest.md#_checkinit)
- [decrypt](NonRepudiationDest.md#decrypt)
- [generatePoR](NonRepudiationDest.md#generatepor)
- [init](NonRepudiationDest.md#init)
- [verifyPoO](NonRepudiationDest.md#verifypoo)
- [verifyPoP](NonRepudiationDest.md#verifypop)

## Constructors

### constructor

• **new NonRepudiationDest**(`exchangeId`, `jwkPairDest`, `publicJwkOrig`)

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `exchangeId` | `string` | the id of this data exchange. It MUST be unique for the same origin and destination |
| `jwkPairDest` | [`JwkPair`](../interfaces/JwkPair.md) | a pair of private and public keys owned by this entity (non-repudiation dest) |
| `publicJwkOrig` | [`JWK`](../interfaces/JWK.md) | the public key as a JWK of the other peer (non-repudiation orig) |

#### Defined in

[src/ts/NonRepudiationDest.ts:28](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationDest.ts#L28)

## Properties

### block

• `Optional` **block**: [`DestBlock`](../interfaces/DestBlock.md)

#### Defined in

[src/ts/NonRepudiationDest.ts:19](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationDest.ts#L19)

___

### checked

• **checked**: `boolean`

#### Defined in

[src/ts/NonRepudiationDest.ts:20](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationDest.ts#L20)

___

### exchange

• **exchange**: [`DataExchangeInit`](../interfaces/DataExchangeInit.md)

#### Defined in

[src/ts/NonRepudiationDest.ts:16](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationDest.ts#L16)

___

### jwkPairDest

• **jwkPairDest**: [`JwkPair`](../interfaces/JwkPair.md)

#### Defined in

[src/ts/NonRepudiationDest.ts:17](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationDest.ts#L17)

___

### publicJwkOrig

• **publicJwkOrig**: [`JWK`](../interfaces/JWK.md)

#### Defined in

[src/ts/NonRepudiationDest.ts:18](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationDest.ts#L18)

## Methods

### \_checkInit

▸ `Private` **_checkInit**(): `void`

#### Returns

`void`

#### Defined in

[src/ts/NonRepudiationDest.ts:161](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationDest.ts#L161)

___

### decrypt

▸ **decrypt**(): `Promise`<`Uint8Array`\>

Decrypts the cipherblock once all the previous proofs have been verified

**`throws`** Error if the previous proofs have not been verified or the decrypted block does not meet the committed one

#### Returns

`Promise`<`Uint8Array`\>

the decrypted block

#### Defined in

[src/ts/NonRepudiationDest.ts:144](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationDest.ts#L144)

___

### generatePoR

▸ **generatePoR**(): `Promise`<`string`\>

Creates the proof of reception (PoR).
Besides returning its value, it is also stored in `this.block.por`

#### Returns

`Promise`<`string`\>

a compact JWS with the PoR

#### Defined in

[src/ts/NonRepudiationDest.ts:87](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationDest.ts#L87)

___

### init

▸ **init**(): `Promise`<`void`\>

Initialize this instance. It MUST be invoked before calling any other method.

#### Returns

`Promise`<`void`\>

#### Defined in

[src/ts/NonRepudiationDest.ts:43](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationDest.ts#L43)

___

### verifyPoO

▸ **verifyPoO**(`poo`, `cipherblock`): `Promise`<[`JWTVerifyResult`](../interfaces/JWTVerifyResult.md)\>

Verifies a proof of origin against the received cipherblock.
If verification passes, `pop` and `cipherblock` are added to this.block

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `poo` | `string` | a Proof of Origin (PoO) in compact JWS format |
| `cipherblock` | `string` | a cipherblock as a JWE |

#### Returns

`Promise`<[`JWTVerifyResult`](../interfaces/JWTVerifyResult.md)\>

the verified payload and protected header

#### Defined in

[src/ts/NonRepudiationDest.ts:57](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationDest.ts#L57)

___

### verifyPoP

▸ **verifyPoP**(`pop`, `secret`): `Promise`<[`JWTVerifyResult`](../interfaces/JWTVerifyResult.md)\>

Verifies a received Proof of Publication (PoP) with the received secret and verificationCode

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `pop` | `string` | a PoP in compact JWS |
| `secret` | [`JWK`](../interfaces/JWK.md) | the JWK secret that was used to encrypt the block |

#### Returns

`Promise`<[`JWTVerifyResult`](../interfaces/JWTVerifyResult.md)\>

the verified payload and protected header

#### Defined in

[src/ts/NonRepudiationDest.ts:111](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationDest.ts#L111)
