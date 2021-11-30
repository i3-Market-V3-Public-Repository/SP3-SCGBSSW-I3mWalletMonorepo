# @i3-market/non-repudiation-proofs - v0.9.1

My module description. Please update with your module data.

**`remarks`**
This module runs perfectly in node.js and browsers

## Table of contents

### Interfaces

- [PoO](interfaces/PoO.md)
- [PoR](interfaces/PoR.md)
- [account](interfaces/account.md)

### Variables

- [SIGNING\_ALG](API.md#signing_alg)

### Functions

- [createBlockchainProof](API.md#createblockchainproof)
- [createJwk](API.md#createjwk)
- [createPoO](API.md#createpoo)
- [createPoR](API.md#createpor)
- [decodePoo](API.md#decodepoo)
- [decodePor](API.md#decodepor)
- [decryptCipherblock](API.md#decryptcipherblock)
- [sha](API.md#sha)
- [signProof](API.md#signproof)
- [validateCipherblock](API.md#validatecipherblock)
- [validatePoO](API.md#validatepoo)
- [validatePoP](API.md#validatepop)
- [validatePoR](API.md#validatepor)

## Variables

### SIGNING\_ALG

• **SIGNING\_ALG**: ``"ES256"``

#### Defined in

[createProofs.ts:6](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/a3055d8/src/ts/createProofs.ts#L6)

## Functions

### createBlockchainProof

▸ `Const` **createBlockchainProof**(`publicKey`, `poO`, `poR`, `jwk`): `Promise`<[`account`](interfaces/account.md)\>

Prepare block to be send to the Backplain API

#### Parameters

| Name | Type |
| :------ | :------ |
| `publicKey` | `KeyLike` |
| `poO` | `string` |
| `poR` | `string` |
| `jwk` | `JWK` |

#### Returns

`Promise`<[`account`](interfaces/account.md)\>

#### Defined in

[createProofs.ts:120](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/a3055d8/src/ts/createProofs.ts#L120)

___

### createJwk

▸ `Const` **createJwk**(): `Promise`<`JWK`\>

Create a random (high entropy) symmetric JWK secret

#### Returns

`Promise`<`JWK`\>

a promise that resolves to a JWK

#### Defined in

[createProofs.ts:60](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/a3055d8/src/ts/createProofs.ts#L60)

___

### createPoO

▸ `Const` **createPoO**(`privateKey`, `block`, `providerId`, `consumerId`, `exchangeId`, `blockId`, `jwk`): `Promise`<{ `cipherblock`: `string` ; `poO`: `string`  }\>

Create Proof of Origin and sign with Provider private key

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `privateKey` | `KeyLike` | private key of the signer/issuer |
| `block` | `string` \| `ArrayBufferLike` | the blocks asdfsdfsd |
| `providerId` | `string` |  |
| `consumerId` | `string` |  |
| `exchangeId` | `number` |  |
| `blockId` | `number` |  |
| `jwk` | `JWK` |  |

#### Returns

`Promise`<{ `cipherblock`: `string` ; `poO`: `string`  }\>

#### Defined in

[createProofs.ts:23](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/a3055d8/src/ts/createProofs.ts#L23)

___

### createPoR

▸ `Const` **createPoR**(`privateKey`, `poO`, `providerId`, `consumerId`, `exchangeId`): `Promise`<`string`\>

Create Proof of Receipt and sign with Consumer private key

#### Parameters

| Name | Type |
| :------ | :------ |
| `privateKey` | `KeyLike` |
| `poO` | `string` |
| `providerId` | `string` |
| `consumerId` | `string` |
| `exchangeId` | `number` |

#### Returns

`Promise`<`string`\>

#### Defined in

[createProofs.ts:98](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/a3055d8/src/ts/createProofs.ts#L98)

___

### decodePoo

▸ `Const` **decodePoo**(`publicKey`, `poO`): `Promise`<[`PoO`](interfaces/PoO.md)\>

Decode Proof of Origin with Provider public key

#### Parameters

| Name | Type |
| :------ | :------ |
| `publicKey` | `KeyLike` |
| `poO` | `string` |

#### Returns

`Promise`<[`PoO`](interfaces/PoO.md)\>

#### Defined in

[validateProofs.ts:54](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/a3055d8/src/ts/validateProofs.ts#L54)

___

### decodePor

▸ `Const` **decodePor**(`publicKey`, `poR`): `Promise`<[`PoR`](interfaces/PoR.md)\>

Decode Proof of Reception with Consumer public key

#### Parameters

| Name | Type |
| :------ | :------ |
| `publicKey` | `KeyLike` |
| `poR` | `string` |

#### Returns

`Promise`<[`PoR`](interfaces/PoR.md)\>

#### Defined in

[validateProofs.ts:27](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/a3055d8/src/ts/validateProofs.ts#L27)

___

### decryptCipherblock

▸ `Const` **decryptCipherblock**(`chiperblock`, `jwk`): `Promise`<`string`\>

Decrypt the cipherblock received

#### Parameters

| Name | Type |
| :------ | :------ |
| `chiperblock` | `string` |
| `jwk` | `JWK` |

#### Returns

`Promise`<`string`\>

#### Defined in

[validateProofs.ts:90](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/a3055d8/src/ts/validateProofs.ts#L90)

___

### sha

▸ `Const` **sha**(`input`, `algorithm?`): `Promise`<`string`\>

#### Parameters

| Name | Type | Default value |
| :------ | :------ | :------ |
| `input` | `string` \| `Uint8Array` | `undefined` |
| `algorithm` | `string` | `'SHA-256'` |

#### Returns

`Promise`<`string`\>

#### Defined in

[sha.ts:1](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/a3055d8/src/ts/sha.ts#L1)

___

### signProof

▸ `Const` **signProof**(`privateKey`, `proof`): `Promise`<`string`\>

Sign a proof with private key

#### Parameters

| Name | Type |
| :------ | :------ |
| `privateKey` | `KeyLike` |
| `proof` | `any` |

#### Returns

`Promise`<`string`\>

#### Defined in

[createProofs.ts:86](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/a3055d8/src/ts/createProofs.ts#L86)

___

### validateCipherblock

▸ `Const` **validateCipherblock**(`publicKey`, `chiperblock`, `jwk`, `poO`): `Promise`<`boolean`\>

Validate the cipherblock

#### Parameters

| Name | Type |
| :------ | :------ |
| `publicKey` | `KeyLike` |
| `chiperblock` | `string` |
| `jwk` | `JWK` |
| `poO` | [`PoO`](interfaces/PoO.md) |

#### Returns

`Promise`<`boolean`\>

#### Defined in

[validateProofs.ts:101](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/a3055d8/src/ts/validateProofs.ts#L101)

___

### validatePoO

▸ `Const` **validatePoO**(`publicKey`, `poO`, `cipherblock`): `Promise`<`boolean`\>

Validate Proof or Origin using the Consumer Public Key

#### Parameters

| Name | Type |
| :------ | :------ |
| `publicKey` | `KeyLike` |
| `poO` | `string` |
| `cipherblock` | `string` |

#### Returns

`Promise`<`boolean`\>

#### Defined in

[validateProofs.ts:38](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/a3055d8/src/ts/validateProofs.ts#L38)

___

### validatePoP

▸ `Const` **validatePoP**(`publicKeyBackplain`, `publicKeyProvider`, `poP`, `jwk`, `poO`): `Promise`<`boolean`\>

Validate Proof of Publication using the Backplain Public Key

#### Parameters

| Name | Type |
| :------ | :------ |
| `publicKeyBackplain` | `KeyLike` |
| `publicKeyProvider` | `KeyLike` |
| `poP` | `string` |
| `jwk` | `JWK` |
| `poO` | `string` |

#### Returns

`Promise`<`boolean`\>

#### Defined in

[validateProofs.ts:65](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/a3055d8/src/ts/validateProofs.ts#L65)

___

### validatePoR

▸ `Const` **validatePoR**(`publicKey`, `poR`, `poO`): `Promise`<`boolean`\>

Validate Proof or Request using the Provider Public Key

#### Parameters

| Name | Type |
| :------ | :------ |
| `publicKey` | `KeyLike` |
| `poR` | `string` |
| `poO` | `string` |

#### Returns

`Promise`<`boolean`\>

#### Defined in

[validateProofs.ts:11](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/a3055d8/src/ts/validateProofs.ts#L11)
