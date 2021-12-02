# Class: NonRepudiationDest

## Table of contents

### Constructors

- [constructor](NonRepudiationDest.md#constructor)

### Properties

- [block](NonRepudiationDest.md#block)
- [checked](NonRepudiationDest.md#checked)
- [dataExchange](NonRepudiationDest.md#dataexchange)
- [jwkPairDest](NonRepudiationDest.md#jwkpairdest)
- [publicJwkOrig](NonRepudiationDest.md#publicjwkorig)

### Methods

- [\_checkInit](NonRepudiationDest.md#_checkinit)
- [generatePoR](NonRepudiationDest.md#generatepor)
- [init](NonRepudiationDest.md#init)
- [verifyPoO](NonRepudiationDest.md#verifypoo)
- [verifyPoPAndDecrypt](NonRepudiationDest.md#verifypopanddecrypt)

## Constructors

### constructor

• **new NonRepudiationDest**(`dataExchangeId`, `jwkPairDest`, `publicJwkOrig`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `dataExchangeId` | `string` |
| `jwkPairDest` | [`JwkPair`](../interfaces/JwkPair.md) |
| `publicJwkOrig` | [`JWK`](../interfaces/JWK.md) |

#### Defined in

src/ts/NonRepudiationDest.ts:26

## Properties

### block

• `Optional` **block**: `Block`

#### Defined in

src/ts/NonRepudiationDest.ts:23

___

### checked

• **checked**: `boolean`

#### Defined in

src/ts/NonRepudiationDest.ts:24

___

### dataExchange

• **dataExchange**: [`DataExchangeInit`](../interfaces/DataExchangeInit.md)

#### Defined in

src/ts/NonRepudiationDest.ts:20

___

### jwkPairDest

• **jwkPairDest**: [`JwkPair`](../interfaces/JwkPair.md)

#### Defined in

src/ts/NonRepudiationDest.ts:21

___

### publicJwkOrig

• **publicJwkOrig**: [`JWK`](../interfaces/JWK.md)

#### Defined in

src/ts/NonRepudiationDest.ts:22

## Methods

### \_checkInit

▸ `Private` **_checkInit**(): `void`

#### Returns

`void`

#### Defined in

src/ts/NonRepudiationDest.ts:117

___

### generatePoR

▸ **generatePoR**(): `Promise`<`string`\>

Creates the proof of reception (PoR) as a compact JWS for the block of data. Besides returning its value, it is also stored in this.block.por

#### Returns

`Promise`<`string`\>

#### Defined in

src/ts/NonRepudiationDest.ts:71

___

### init

▸ **init**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

src/ts/NonRepudiationDest.ts:38

___

### verifyPoO

▸ **verifyPoO**(`poo`, `cipherblock`): `Promise`<[`JWTVerifyResult`](../interfaces/JWTVerifyResult.md)\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `poo` | `string` |
| `cipherblock` | `string` |

#### Returns

`Promise`<[`JWTVerifyResult`](../interfaces/JWTVerifyResult.md)\>

#### Defined in

src/ts/NonRepudiationDest.ts:43

___

### verifyPoPAndDecrypt

▸ **verifyPoPAndDecrypt**(`pop`, `secret`, `verificationCode`): `Promise`<{ `decryptedBlock`: `Uint8Array` ; `verified`: [`JWTVerifyResult`](../interfaces/JWTVerifyResult.md)  }\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `pop` | `string` |
| `secret` | `string` |
| `verificationCode` | `string` |

#### Returns

`Promise`<{ `decryptedBlock`: `Uint8Array` ; `verified`: [`JWTVerifyResult`](../interfaces/JWTVerifyResult.md)  }\>

#### Defined in

src/ts/NonRepudiationDest.ts:88
