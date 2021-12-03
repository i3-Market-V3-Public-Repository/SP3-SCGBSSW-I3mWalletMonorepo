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

[src/ts/NonRepudiationOrig.ts:27](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/d1778d3/src/ts/NonRepudiationOrig.ts#L27)

## Properties

### block

• **block**: `Block`

#### Defined in

[src/ts/NonRepudiationOrig.ts:24](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/d1778d3/src/ts/NonRepudiationOrig.ts#L24)

___

### checked

• **checked**: `boolean`

#### Defined in

[src/ts/NonRepudiationOrig.ts:25](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/d1778d3/src/ts/NonRepudiationOrig.ts#L25)

___

### dataExchange

• **dataExchange**: [`DataExchangeInit`](../interfaces/DataExchangeInit.md)

#### Defined in

[src/ts/NonRepudiationOrig.ts:21](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/d1778d3/src/ts/NonRepudiationOrig.ts#L21)

___

### jwkPairOrig

• **jwkPairOrig**: [`JwkPair`](../interfaces/JwkPair.md)

#### Defined in

[src/ts/NonRepudiationOrig.ts:22](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/d1778d3/src/ts/NonRepudiationOrig.ts#L22)

___

### publicJwkDest

• **publicJwkDest**: [`JWK`](../interfaces/JWK.md)

#### Defined in

[src/ts/NonRepudiationOrig.ts:23](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/d1778d3/src/ts/NonRepudiationOrig.ts#L23)

## Methods

### \_checkInit

▸ `Private` **_checkInit**(): `void`

#### Returns

`void`

#### Defined in

[src/ts/NonRepudiationOrig.ts:121](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/d1778d3/src/ts/NonRepudiationOrig.ts#L121)

___

### generatePoO

▸ **generatePoO**(): `Promise`<`string`\>

Creates the proof of origin (PoO) as a compact JWS for the block of data. Besides returning its value, it is also stored in this.block.poo

#### Returns

`Promise`<`string`\>

#### Defined in

[src/ts/NonRepudiationOrig.ts:71](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/d1778d3/src/ts/NonRepudiationOrig.ts#L71)

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

[src/ts/NonRepudiationOrig.ts:102](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/d1778d3/src/ts/NonRepudiationOrig.ts#L102)

___

### init

▸ **init**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

[src/ts/NonRepudiationOrig.ts:50](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/d1778d3/src/ts/NonRepudiationOrig.ts#L50)

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

[src/ts/NonRepudiationOrig.ts:83](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/d1778d3/src/ts/NonRepudiationOrig.ts#L83)
