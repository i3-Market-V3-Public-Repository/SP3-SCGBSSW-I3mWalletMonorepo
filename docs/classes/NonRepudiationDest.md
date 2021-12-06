# Class: NonRepudiationDest

The base class that should be instantiated by the destination of a data
exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
likely to be a Consumer.

## Table of contents

### Constructors

- [constructor](NonRepudiationDest.md#constructor)

### Properties

- [block](NonRepudiationDest.md#block)
- [dltConfig](NonRepudiationDest.md#dltconfig)
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

• **new NonRepudiationDest**(`exchangeId`, `jwkPairDest`, `publicJwkOrig`, `dltConfig?`, `algs?`)

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `exchangeId` | `string` | the id of this data exchange. It is a unique identifier as the base64url-no-padding encoding of a uint256 |
| `jwkPairDest` | [`JwkPair`](../interfaces/JwkPair.md) | a pair of private and public keys owned by this entity (non-repudiation dest) |
| `publicJwkOrig` | [`JWK`](../interfaces/JWK.md) | the public key as a JWK of the other peer (non-repudiation orig) |
| `dltConfig?` | `Partial`<[`DltConfig`](../interfaces/DltConfig.md)\> | an object with the necessary configuration for the (Ethereum-like) DLT |
| `algs?` | [`Algs`](../interfaces/Algs.md) | is used to overwrite the default algorithms for hash (SHA-256), signing (ES256) and encryption (A256GM) |

#### Defined in

[src/ts/NonRepudiationDest.ts:38](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/db9e1a9/src/ts/NonRepudiationDest.ts#L38)

## Properties

### block

• **block**: [`Block`](../interfaces/Block.md)

#### Defined in

[src/ts/NonRepudiationDest.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/db9e1a9/src/ts/NonRepudiationDest.ts#L26)

___

### dltConfig

• **dltConfig**: [`DltConfig`](../interfaces/DltConfig.md)

#### Defined in

[src/ts/NonRepudiationDest.ts:27](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/db9e1a9/src/ts/NonRepudiationDest.ts#L27)

___

### exchange

• **exchange**: [`DataExchangeInit`](../interfaces/DataExchangeInit.md)

#### Defined in

[src/ts/NonRepudiationDest.ts:23](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/db9e1a9/src/ts/NonRepudiationDest.ts#L23)

___

### initialized

• **initialized**: `Promise`<`boolean`\>

#### Defined in

[src/ts/NonRepudiationDest.ts:28](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/db9e1a9/src/ts/NonRepudiationDest.ts#L28)

___

### jwkPairDest

• **jwkPairDest**: [`JwkPair`](../interfaces/JwkPair.md)

#### Defined in

[src/ts/NonRepudiationDest.ts:24](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/db9e1a9/src/ts/NonRepudiationDest.ts#L24)

___

### publicJwkOrig

• **publicJwkOrig**: [`JWK`](../interfaces/JWK.md)

#### Defined in

[src/ts/NonRepudiationDest.ts:25](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/db9e1a9/src/ts/NonRepudiationDest.ts#L25)

## Methods

### \_dltSetup

▸ `Private` **_dltSetup**(`providedDltConfig?`): [`DltConfig`](../interfaces/DltConfig.md)

#### Parameters

| Name | Type |
| :------ | :------ |
| `providedDltConfig?` | `Partial`<[`DltConfig`](../interfaces/DltConfig.md)\> |

#### Returns

[`DltConfig`](../interfaces/DltConfig.md)

#### Defined in

[src/ts/NonRepudiationDest.ts:63](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/db9e1a9/src/ts/NonRepudiationDest.ts#L63)

___

### decrypt

▸ **decrypt**(): `Promise`<`Uint8Array`\>

Decrypts the cipherblock once all the previous proofs have been verified

**`throws`** Error if the previous proofs have not been verified or the decrypted block does not meet the committed one

#### Returns

`Promise`<`Uint8Array`\>

the decrypted block

#### Defined in

[src/ts/NonRepudiationDest.ts:207](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/db9e1a9/src/ts/NonRepudiationDest.ts#L207)

___

### generatePoR

▸ **generatePoR**(): `Promise`<`string`\>

Creates the proof of reception (PoR).
Besides returning its value, it is also stored in `this.block.por`

#### Returns

`Promise`<`string`\>

a compact JWS with the PoR

#### Defined in

[src/ts/NonRepudiationDest.ts:124](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/db9e1a9/src/ts/NonRepudiationDest.ts#L124)

___

### getSecretFromLedger

▸ **getSecretFromLedger**(`timeout?`): `Promise`<{ `hex`: `string` ; `jwk`: [`JWK`](../interfaces/JWK.md)  }\>

Just in case the PoP is not received, the secret can be downloaded from the ledger

#### Parameters

| Name | Type | Default value | Description |
| :------ | :------ | :------ | :------ |
| `timeout` | `number` | `20` | the time in seconds to wait for the query to get the value |

#### Returns

`Promise`<{ `hex`: `string` ; `jwk`: [`JWK`](../interfaces/JWK.md)  }\>

the secret

#### Defined in

[src/ts/NonRepudiationDest.ts:182](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/db9e1a9/src/ts/NonRepudiationDest.ts#L182)

___

### init

▸ **init**(): `Promise`<`void`\>

Initialize this instance. It MUST be invoked before calling any other method.

#### Returns

`Promise`<`void`\>

#### Defined in

[src/ts/NonRepudiationDest.ts:81](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/db9e1a9/src/ts/NonRepudiationDest.ts#L81)

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

[src/ts/NonRepudiationDest.ts:94](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/db9e1a9/src/ts/NonRepudiationDest.ts#L94)

___

### verifyPoP

▸ **verifyPoP**(`pop`): `Promise`<[`JWTVerifyResult`](../interfaces/JWTVerifyResult.md)\>

Verifies a received Proof of Publication (PoP) and returns the secret

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `pop` | `string` | a PoP in compact JWS |

#### Returns

`Promise`<[`JWTVerifyResult`](../interfaces/JWTVerifyResult.md)\>

the verified payload (that includes the secret that can be used to decrypt the cipherblock) and protected header

#### Defined in

[src/ts/NonRepudiationDest.ts:147](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/db9e1a9/src/ts/NonRepudiationDest.ts#L147)
