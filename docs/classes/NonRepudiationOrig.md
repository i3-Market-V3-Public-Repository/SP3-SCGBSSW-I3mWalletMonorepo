# Class: NonRepudiationOrig

The base class that should be instantiated by the origin of a data
exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
likely to be a Provider.

## Table of contents

### Constructors

- [constructor](NonRepudiationOrig.md#constructor)

### Properties

- [block](NonRepudiationOrig.md#block)
- [dltConfig](NonRepudiationOrig.md#dltconfig)
- [exchange](NonRepudiationOrig.md#exchange)
- [initialized](NonRepudiationOrig.md#initialized)
- [jwkPairOrig](NonRepudiationOrig.md#jwkpairorig)
- [publicJwkDest](NonRepudiationOrig.md#publicjwkdest)

### Methods

- [\_dltSetup](NonRepudiationOrig.md#_dltsetup)
- [generatePoO](NonRepudiationOrig.md#generatepoo)
- [generatePoP](NonRepudiationOrig.md#generatepop)
- [init](NonRepudiationOrig.md#init)
- [verifyPoR](NonRepudiationOrig.md#verifypor)

## Constructors

### constructor

• **new NonRepudiationOrig**(`exchangeId`, `jwkPairOrig`, `publicJwkDest`, `block`, `dltConfig?`, `algs?`)

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `exchangeId` | `string` | the id of this data exchange. It MUST be unique for the sender |
| `jwkPairOrig` | [`JwkPair`](../interfaces/JwkPair.md) | a pair of private and public keys owned by this entity (non-repudiation orig) |
| `publicJwkDest` | [`JWK`](../interfaces/JWK.md) | the public key as a JWK of the other peer (non-repudiation dest) |
| `block` | `Uint8Array` | the block of data to transmit in this data exchange |
| `dltConfig?` | `Partial`<[`DltConfig`](../interfaces/DltConfig.md)\> | an object with the necessary configuration for the (Ethereum-like) DLT |
| `algs?` | [`Algs`](../interfaces/Algs.md) | is used to overwrite the default algorithms for hash (SHA-256), signing (ES256) and encryption (A256GCM) |

#### Defined in

[src/ts/NonRepudiationOrig.ts:37](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/NonRepudiationOrig.ts#L37)

## Properties

### block

• **block**: [`OrigBlock`](../interfaces/OrigBlock.md)

#### Defined in

[src/ts/NonRepudiationOrig.ts:25](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/NonRepudiationOrig.ts#L25)

___

### dltConfig

• **dltConfig**: [`DltConfig`](../interfaces/DltConfig.md)

#### Defined in

[src/ts/NonRepudiationOrig.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/NonRepudiationOrig.ts#L26)

___

### exchange

• **exchange**: [`DataExchangeInit`](../interfaces/DataExchangeInit.md)

#### Defined in

[src/ts/NonRepudiationOrig.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/NonRepudiationOrig.ts#L22)

___

### initialized

• **initialized**: `Promise`<`boolean`\>

#### Defined in

[src/ts/NonRepudiationOrig.ts:27](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/NonRepudiationOrig.ts#L27)

___

### jwkPairOrig

• **jwkPairOrig**: [`JwkPair`](../interfaces/JwkPair.md)

#### Defined in

[src/ts/NonRepudiationOrig.ts:23](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/NonRepudiationOrig.ts#L23)

___

### publicJwkDest

• **publicJwkDest**: [`JWK`](../interfaces/JWK.md)

#### Defined in

[src/ts/NonRepudiationOrig.ts:24](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/NonRepudiationOrig.ts#L24)

## Methods

### \_dltSetup

▸ `Private` **_dltSetup**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

[src/ts/NonRepudiationOrig.ts:96](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/NonRepudiationOrig.ts#L96)

___

### generatePoO

▸ **generatePoO**(): `Promise`<`string`\>

Creates the proof of origin (PoO).
Besides returning its value, it is also stored in this.block.poo

#### Returns

`Promise`<`string`\>

a compact JWS with the PoO

#### Defined in

[src/ts/NonRepudiationOrig.ts:129](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/NonRepudiationOrig.ts#L129)

___

### generatePoP

▸ **generatePoP**(): `Promise`<`string`\>

Creates the proof of publication (PoP).
Besides returning its value, it is also stored in `this.block.pop`

#### Returns

`Promise`<`string`\>

a compact JWS with the PoP

#### Defined in

[src/ts/NonRepudiationOrig.ts:173](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/NonRepudiationOrig.ts#L173)

___

### init

▸ **init**(): `Promise`<`void`\>

Initialize this instance. It MUST be invoked before calling any other method.

#### Returns

`Promise`<`void`\>

#### Defined in

[src/ts/NonRepudiationOrig.ts:76](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/NonRepudiationOrig.ts#L76)

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

[src/ts/NonRepudiationOrig.ts:148](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/NonRepudiationOrig.ts#L148)
