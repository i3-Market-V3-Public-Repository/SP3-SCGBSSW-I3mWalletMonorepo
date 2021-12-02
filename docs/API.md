# @i3-market/non-repudiation-proofs - v0.9.1

i3-Market implementation of the non-repudiation proofs of a data exchange

## Table of contents

### Classes

- [NonRepudiationDest](classes/NonRepudiationDest.md)
- [NonRepudiationOrig](classes/NonRepudiationOrig.md)

### Interfaces

- [CompactDecryptResult](interfaces/CompactDecryptResult.md)
- [DataExchange](interfaces/DataExchange.md)
- [DataExchangeInit](interfaces/DataExchangeInit.md)
- [DateTolerance](interfaces/DateTolerance.md)
- [JWK](interfaces/JWK.md)
- [JWTVerifyResult](interfaces/JWTVerifyResult.md)
- [JwkPair](interfaces/JwkPair.md)
- [PoOPayload](interfaces/PoOPayload.md)
- [PoPPayload](interfaces/PoPPayload.md)
- [PoRPayload](interfaces/PoRPayload.md)

### Type aliases

- [ProofInputPayload](API.md#proofinputpayload)
- [ProofPayload](API.md#proofpayload)

### Variables

- [ENC\_ALG](API.md#enc_alg)
- [HASH\_ALG](API.md#hash_alg)
- [SIGNING\_ALG](API.md#signing_alg)

### Functions

- [createProof](API.md#createproof)
- [jweDecrypt](API.md#jwedecrypt)
- [jweEncrypt](API.md#jweencrypt)
- [oneTimeSecret](API.md#onetimesecret)
- [sha](API.md#sha)
- [verifyKeyPair](API.md#verifykeypair)
- [verifyProof](API.md#verifyproof)

## Type aliases

### ProofInputPayload

Ƭ **ProofInputPayload**: [`PoOPayload`](interfaces/PoOPayload.md) \| [`PoRPayload`](interfaces/PoRPayload.md) \| [`PoPPayload`](interfaces/PoPPayload.md)

#### Defined in

src/ts/types.ts:58

___

### ProofPayload

Ƭ **ProofPayload**: [`ProofInputPayload`](API.md#proofinputpayload) & { `iat`: `number`  }

#### Defined in

src/ts/types.ts:60

## Variables

### ENC\_ALG

• **ENC\_ALG**: ``"A128GCM"`` \| ``"A192GCM"`` \| ``"A256GCM"`` = `'A256GCM'`

#### Defined in

src/ts/constants.ts:3

___

### HASH\_ALG

• **HASH\_ALG**: ``"SHA-256"``

#### Defined in

src/ts/constants.ts:1

___

### SIGNING\_ALG

• **SIGNING\_ALG**: ``"RS256"``

#### Defined in

src/ts/constants.ts:2

## Functions

### createProof

▸ **createProof**(`payload`, `privateJwk`): `Promise`<`string`\>

Creates a non-repudiable proof for a given data exchange

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `payload` | [`ProofInputPayload`](API.md#proofinputpayload) | it must contain a 'dataExchange' the issuer 'iss' (either point to the origin 'orig' or the destination 'dest' of the data exchange) of the proof and any specific proof key-values |
| `privateJwk` | [`JWK`](interfaces/JWK.md) | The private key in JWK that will sign the proof |

#### Returns

`Promise`<`string`\>

a proof as a compact JWS formatted JWT string

#### Defined in

src/ts/createProof.ts:14

___

### jweDecrypt

▸ **jweDecrypt**(`jwe`, `secret`): `Promise`<[`CompactDecryptResult`](interfaces/CompactDecryptResult.md)\>

Decrypts jwe

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `jwe` | `string` | a JWE |
| `secret` | [`JWK`](interfaces/JWK.md) | a JWK with the secret to decrypt this jwe |

#### Returns

`Promise`<[`CompactDecryptResult`](interfaces/CompactDecryptResult.md)\>

the plaintext

#### Defined in

src/ts/jwe.ts:29

___

### jweEncrypt

▸ **jweEncrypt**(`exchangeId`, `block`, `secret`): `Promise`<`string`\>

Encrypts block to JWE

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `exchangeId` | `string` | the id of the data exchange |
| `block` | `Uint8Array` | the actual block of data |
| `secret` | [`JWK`](interfaces/JWK.md) | a one-time secret for encrypting this block |

#### Returns

`Promise`<`string`\>

a Compact JWE

#### Defined in

src/ts/jwe.ts:15

___

### oneTimeSecret

▸ **oneTimeSecret**(): `Promise`<[`JWK`](interfaces/JWK.md)\>

Create a random (high entropy) symmetric JWK secret for AES-256-GCM

#### Returns

`Promise`<[`JWK`](interfaces/JWK.md)\>

a promise that resolves to a JWK

#### Defined in

src/ts/oneTimeSecret.ts:10

___

### sha

▸ **sha**(`input`, `algorithm?`): `Promise`<`string`\>

#### Parameters

| Name | Type | Default value |
| :------ | :------ | :------ |
| `input` | `string` \| `Uint8Array` | `undefined` |
| `algorithm` | `string` | `HASH_ALG` |

#### Returns

`Promise`<`string`\>

#### Defined in

[src/ts/sha.ts:3](https://gitlab.com/i3-market/code/wp3/t3.3/non-repudiable-exchange/non-repudiable-proofs/-/blob/aa9b704/src/ts/sha.ts#L3)

___

### verifyKeyPair

▸ **verifyKeyPair**(`pubJWK`, `privJWK`, `alg?`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `pubJWK` | [`JWK`](interfaces/JWK.md) |
| `privJWK` | [`JWK`](interfaces/JWK.md) |
| `alg?` | `string` |

#### Returns

`Promise`<`void`\>

#### Defined in

src/ts/verifyKeyPair.ts:5

___

### verifyProof

▸ **verifyProof**(`proof`, `publicJwk`, `expectedPayloadClaims`, `dateTolerance?`): `Promise`<[`JWTVerifyResult`](interfaces/JWTVerifyResult.md)\>

Verify a proof

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `proof` | `string` | a non-repudiable proof in Compact JWS formatted JWT string |
| `publicJwk` | [`JWK`](interfaces/JWK.md) | the publicKey as a JWK to use for verifying the signature. If MUST match either orig or dest (the one pointed on the iss field) |
| `expectedPayloadClaims` | [`ProofInputPayload`](API.md#proofinputpayload) | The expected values of the proof's payload claims. An example could be: {   proofType: 'PoO',   iss: 'orig',   dateExchange: {     id: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',     orig: '{"kty":"EC","x":"rPMP39e-o8cU6m4WL8_qd2wxo-nBTjWXZtPGBiiGCTY","y":"0uvxGEebFDxKOHYUlHREzq4mRULuZvQ6LB2I11yE1E0","crv":"P-256"}', // Public key in JSON.stringify(JWK) of the block origin (sender)     dest: '{"kty":"EC","x":"qf_mNdy57ia1vAq5QLpTPxJUCRhS2003-gL0nLcbXoA","y":"H_8YwSCKJhDbZv17YEgDfAiKTaQ8x0jpLYCC2myxAeY","crv":"P-256"}', // Public key in JSON.stringify(JWK) of the block destination (receiver)     hash_alg: 'SHA-256',     cipherblock_dgst: 'IBUIstf98_afbiuh7UaifkasytNih7as-Jah61ls9UI', // hash of the cipherblock in base64url with no padding     block_commitment: 'iHAdgHDQVo6qaD0KqJ9ZMlVmVA3f3AI6uZG0jFqeu14', // hash of the plaintext block in base64url with no padding     secret_commitment: 'svipVfsi6vsoj3Zk_6LWi3k6mMdQOSSY1OrHGnaM5eA' // hash of the secret that can be used to decrypt the block in base64url with no padding   } } |
| `dateTolerance?` | [`DateTolerance`](interfaces/DateTolerance.md) | specifies a time window to accept the proof. An example could be {   currentDate: new Date('2021-10-17T03:24:00'), // Date to use when comparing NumericDate claims, defaults to new Date().   clockTolerance: 10  // string\|number Expected clock tolerance in seconds when number (e.g. 5), or parsed as seconds when a string (e.g. "5 seconds", "10 minutes", "2 hours") } |

#### Returns

`Promise`<[`JWTVerifyResult`](interfaces/JWTVerifyResult.md)\>

The JWT protected header and payload if the proof is validated

#### Defined in

src/ts/verifyProof.ts:36
