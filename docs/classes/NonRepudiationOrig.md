# Class: NonRepudiationOrig

## Table of contents

### Constructors

- [constructor](NonRepudiationOrig.md#constructor)

### Properties

- [block](NonRepudiationOrig.md#block)
- [checked](NonRepudiationOrig.md#checked)
- [dataExchange](NonRepudiationOrig.md#dataexchange)
- [jwkPairOrig](NonRepudiationOrig.md#jwkpairorig)
- [publicJwkDest](NonRepudiationOrig.md#publicjwkdest)

### Methods

- [\_checkInit](NonRepudiationOrig.md#_checkinit)
- [generatePoO](NonRepudiationOrig.md#generatepoo)
- [generatePoP](NonRepudiationOrig.md#generatepop)
- [init](NonRepudiationOrig.md#init)
- [verifyPoR](NonRepudiationOrig.md#verifypor)

## Constructors

### constructor

• **new NonRepudiationOrig**(`dataExchangeId`, `jwkPairOrig`, `publicJwkDest`, `block`, `alg?`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `dataExchangeId` | `string` |
| `jwkPairOrig` | [`JwkPair`](../interfaces/JwkPair.md) |
| `publicJwkDest` | [`JWK`](../interfaces/JWK.md) |
| `block` | `Uint8Array` |
| `alg?` | `string` |

#### Defined in

src/ts/NonRepudiationOrig.ts:27

## Properties

### block

• **block**: `Block`

#### Defined in

src/ts/NonRepudiationOrig.ts:24

___

### checked

• **checked**: `boolean`

#### Defined in

src/ts/NonRepudiationOrig.ts:25

___

### dataExchange

• **dataExchange**: [`DataExchangeInit`](../interfaces/DataExchangeInit.md)

#### Defined in

src/ts/NonRepudiationOrig.ts:21

___

### jwkPairOrig

• **jwkPairOrig**: [`JwkPair`](../interfaces/JwkPair.md)

#### Defined in

src/ts/NonRepudiationOrig.ts:22

___

### publicJwkDest

• **publicJwkDest**: [`JWK`](../interfaces/JWK.md)

#### Defined in

src/ts/NonRepudiationOrig.ts:23

## Methods

### \_checkInit

▸ `Private` **_checkInit**(): `void`

#### Returns

`void`

#### Defined in

src/ts/NonRepudiationOrig.ts:121

___

### generatePoO

▸ **generatePoO**(): `Promise`<`string`\>

Creates the proof of origin (PoO) as a compact JWS for the block of data. Besides returning its value, it is also stored in this.block.poo

#### Returns

`Promise`<`string`\>

#### Defined in

src/ts/NonRepudiationOrig.ts:71

___

### generatePoP

▸ **generatePoP**(`verificationCode`): `Promise`<`string`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `verificationCode` | `string` |

#### Returns

`Promise`<`string`\>

#### Defined in

src/ts/NonRepudiationOrig.ts:102

___

### init

▸ **init**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

src/ts/NonRepudiationOrig.ts:50

___

### verifyPoR

▸ **verifyPoR**(`por`): `Promise`<[`JWTVerifyResult`](../interfaces/JWTVerifyResult.md)\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `por` | `string` |

#### Returns

`Promise`<[`JWTVerifyResult`](../interfaces/JWTVerifyResult.md)\>

#### Defined in

src/ts/NonRepudiationOrig.ts:83
