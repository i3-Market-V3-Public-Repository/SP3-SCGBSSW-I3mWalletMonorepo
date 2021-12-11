# Class: NonRepudiationOrig

The base class that should be instantiated by the origin of a data
exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
likely to be a Provider.

## Table of contents

### Constructors

- [constructor](NonRepudiationOrig.md#constructor)

### Properties

- [agreement](NonRepudiationOrig.md#agreement)
- [block](NonRepudiationOrig.md#block)
- [dltConfig](NonRepudiationOrig.md#dltconfig)
- [dltContract](NonRepudiationOrig.md#dltcontract)
- [exchange](NonRepudiationOrig.md#exchange)
- [jwkPairOrig](NonRepudiationOrig.md#jwkpairorig)
- [publicJwkDest](NonRepudiationOrig.md#publicjwkdest)

### Methods

- [generatePoO](NonRepudiationOrig.md#generatepoo)
- [generatePoP](NonRepudiationOrig.md#generatepop)
- [verifyPoR](NonRepudiationOrig.md#verifypor)

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
| `privateLedgerKeyHex?` | `string` | the private key (d parameter) as a hexadecimal string used to sign transactions to the ledger. If not provided, it is assumed that is the same as privateJwk |

#### Defined in

[src/ts/NonRepudiationOrig.ts:38](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/97869db/src/ts/NonRepudiationOrig.ts#L38)

## Properties

### agreement

• **agreement**: [`DataExchangeAgreement`](../interfaces/DataExchangeAgreement.md)

#### Defined in

[src/ts/NonRepudiationOrig.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/97869db/src/ts/NonRepudiationOrig.ts#L22)

___

### block

• **block**: [`OrigBlock`](../interfaces/OrigBlock.md)

#### Defined in

[src/ts/NonRepudiationOrig.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/97869db/src/ts/NonRepudiationOrig.ts#L26)

___

### dltConfig

• **dltConfig**: [`DltConfig`](../interfaces/DltConfig.md)

#### Defined in

[src/ts/NonRepudiationOrig.ts:27](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/97869db/src/ts/NonRepudiationOrig.ts#L27)

___

### dltContract

• **dltContract**: `Contract`

#### Defined in

[src/ts/NonRepudiationOrig.ts:28](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/97869db/src/ts/NonRepudiationOrig.ts#L28)

___

### exchange

• **exchange**: [`DataExchange`](../interfaces/DataExchange.md)

#### Defined in

[src/ts/NonRepudiationOrig.ts:23](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/97869db/src/ts/NonRepudiationOrig.ts#L23)

___

### jwkPairOrig

• **jwkPairOrig**: [`JwkPair`](../interfaces/JwkPair.md)

#### Defined in

[src/ts/NonRepudiationOrig.ts:24](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/97869db/src/ts/NonRepudiationOrig.ts#L24)

___

### publicJwkDest

• **publicJwkDest**: [`JWK`](../interfaces/JWK.md)

#### Defined in

[src/ts/NonRepudiationOrig.ts:25](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/97869db/src/ts/NonRepudiationOrig.ts#L25)

## Methods

### generatePoO

▸ **generatePoO**(): `Promise`<[`StoredProof`](../interfaces/StoredProof.md)\>

Creates the proof of origin (PoO).
Besides returning its value, it is also stored in this.block.poo

#### Returns

`Promise`<[`StoredProof`](../interfaces/StoredProof.md)\>

a compact JWS with the PoO along with its decoded payload

#### Defined in

[src/ts/NonRepudiationOrig.ts:129](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/97869db/src/ts/NonRepudiationOrig.ts#L129)

___

### generatePoP

▸ **generatePoP**(): `Promise`<[`StoredProof`](../interfaces/StoredProof.md)\>

Creates the proof of publication (PoP).
Besides returning its value, it is also stored in `this.block.pop`

#### Returns

`Promise`<[`StoredProof`](../interfaces/StoredProof.md)\>

a compact JWS with the PoP

#### Defined in

[src/ts/NonRepudiationOrig.ts:189](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/97869db/src/ts/NonRepudiationOrig.ts#L189)

___

### verifyPoR

▸ **verifyPoR**(`por`, `clockToleranceMs?`, `currentDate?`): `Promise`<[`StoredProof`](../interfaces/StoredProof.md)\>

Verifies a proof of reception.
If verification passes, `por` is added to `this.block`

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `por` | `string` | A PoR in caompact JWS format |
| `clockToleranceMs?` | `number` | expected clock tolerance in milliseconds when comparing Dates |
| `currentDate?` | `Date` | check the proof as it were checked in this date |

#### Returns

`Promise`<[`StoredProof`](../interfaces/StoredProof.md)\>

the verified payload and protected header

#### Defined in

[src/ts/NonRepudiationOrig.ts:150](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/97869db/src/ts/NonRepudiationOrig.ts#L150)
