# Class: NonRepudiationOrig

The base class that should be instantiated by the origin of a data
exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
likely to be a Provider.

## Table of contents

### Constructors

- [constructor](NonRepudiationOrig.md#constructor)

### Properties

- [block](NonRepudiationOrig.md#block)
- [checked](NonRepudiationOrig.md#checked)
- [exchange](NonRepudiationOrig.md#exchange)
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

• **new NonRepudiationOrig**(`exchangeId`, `jwkPairOrig`, `publicJwkDest`, `block`, `alg?`)

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `exchangeId` | `string` | the id of this data exchange. It MUST be unique for the same origin and destination |
| `jwkPairOrig` | [`JwkPair`](../interfaces/JwkPair.md) | a pair of private and public keys owned by this entity (non-repudiation orig) |
| `publicJwkDest` | [`JWK`](../interfaces/JWK.md) | the public key as a JWK of the other peer (non-repudiation dest) |
| `block` | `Uint8Array` | the block of data to transmit in this data exchange |
| `alg?` | `string` | the enc alg, if not already in the JWKs |

#### Defined in

[src/ts/NonRepudiationOrig.ts:30](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationOrig.ts#L30)

## Properties

### block

• **block**: [`OrigBlock`](../interfaces/OrigBlock.md)

#### Defined in

[src/ts/NonRepudiationOrig.ts:20](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationOrig.ts#L20)

___

### checked

• **checked**: `boolean`

#### Defined in

[src/ts/NonRepudiationOrig.ts:21](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationOrig.ts#L21)

___

### exchange

• **exchange**: [`DataExchangeInit`](../interfaces/DataExchangeInit.md)

#### Defined in

[src/ts/NonRepudiationOrig.ts:17](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationOrig.ts#L17)

___

### jwkPairOrig

• **jwkPairOrig**: [`JwkPair`](../interfaces/JwkPair.md)

#### Defined in

[src/ts/NonRepudiationOrig.ts:18](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationOrig.ts#L18)

___

### publicJwkDest

• **publicJwkDest**: [`JWK`](../interfaces/JWK.md)

#### Defined in

[src/ts/NonRepudiationOrig.ts:19](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationOrig.ts#L19)

## Methods

### \_checkInit

▸ `Private` **_checkInit**(): `void`

#### Returns

`void`

#### Defined in

[src/ts/NonRepudiationOrig.ts:147](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationOrig.ts#L147)

___

### generatePoO

▸ **generatePoO**(): `Promise`<`string`\>

Creates the proof of origin (PoO).
Besides returning its value, it is also stored in this.block.poo

#### Returns

`Promise`<`string`\>

a compact JWS with the PoO

#### Defined in

[src/ts/NonRepudiationOrig.ts:79](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationOrig.ts#L79)

___

### generatePoP

▸ **generatePoP**(): `Promise`<`string`\>

Creates the proof of publication (PoP).
Besides returning its value, it is also stored in `this.block.pop`

#### Returns

`Promise`<`string`\>

a compact JWS with the PoP

#### Defined in

[src/ts/NonRepudiationOrig.ts:123](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationOrig.ts#L123)

___

### init

▸ **init**(): `Promise`<`void`\>

Initialize this instance. It MUST be invoked before calling any other method.

#### Returns

`Promise`<`void`\>

#### Defined in

[src/ts/NonRepudiationOrig.ts:56](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationOrig.ts#L56)

___

### verifyPoR

▸ **verifyPoR**(`por`): `Promise`<[`JWTVerifyResult`](../interfaces/JWTVerifyResult.md)\>

Verifies a proof of reception.
If verification passes, `por` is added to `this.block`

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `por` | `string` | A PoR in caompact JWS format |

#### Returns

`Promise`<[`JWTVerifyResult`](../interfaces/JWTVerifyResult.md)\>

the verified payload and protected header

#### Defined in

[src/ts/NonRepudiationOrig.ts:98](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/1cd8e09/src/ts/NonRepudiationOrig.ts#L98)
