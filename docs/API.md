# @i3-market/non-repudiation-protocol - v0.9.1

i3-Market implementation of the non-repudiation proofs of a data exchange

## Table of contents

### Classes

- [NonRepudiationDest](classes/NonRepudiationDest.md)
- [NonRepudiationOrig](classes/NonRepudiationOrig.md)

### Interfaces

- [Algs](interfaces/Algs.md)
- [Block](interfaces/Block.md)
- [CompactDecryptResult](interfaces/CompactDecryptResult.md)
- [ContractConfig](interfaces/ContractConfig.md)
- [DataExchange](interfaces/DataExchange.md)
- [DataExchangeInit](interfaces/DataExchangeInit.md)
- [DateTolerance](interfaces/DateTolerance.md)
- [DltConfig](interfaces/DltConfig.md)
- [JWK](interfaces/JWK.md)
- [JWTVerifyResult](interfaces/JWTVerifyResult.md)
- [JwkPair](interfaces/JwkPair.md)
- [OrigBlock](interfaces/OrigBlock.md)
- [PoOPayload](interfaces/PoOPayload.md)
- [PoPPayload](interfaces/PoPPayload.md)
- [PoRPayload](interfaces/PoRPayload.md)
- [Signer](interfaces/Signer.md)

### Type aliases

- [EncryptionAlg](API.md#encryptionalg)
- [HashAlg](API.md#hashalg)
- [ProofInputPayload](API.md#proofinputpayload)
- [ProofPayload](API.md#proofpayload)
- [SigningAlg](API.md#signingalg)

### Functions

- [createProof](API.md#createproof)
- [jweDecrypt](API.md#jwedecrypt)
- [jweEncrypt](API.md#jweencrypt)
- [oneTimeSecret](API.md#onetimesecret)
- [sha](API.md#sha)
- [verifyKeyPair](API.md#verifykeypair)
- [verifyProof](API.md#verifyproof)

## Type aliases

### EncryptionAlg

Ƭ **EncryptionAlg**: ``"A128GCM"`` \| ``"A192GCM"`` \| ``"A256GCM"``

#### Defined in

[src/ts/types.ts:7](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/types.ts#L7)

___

### HashAlg

Ƭ **HashAlg**: ``"SHA-256"`` \| ``"SHA-384"`` \| ``"SHA-512"``

#### Defined in

[src/ts/types.ts:5](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/types.ts#L5)

___

### ProofInputPayload

Ƭ **ProofInputPayload**: [`PoOPayload`](interfaces/PoOPayload.md) \| [`PoRPayload`](interfaces/PoRPayload.md) \| [`PoPPayload`](interfaces/PoPPayload.md)

#### Defined in

[src/ts/types.ts:109](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/types.ts#L109)

___

### ProofPayload

Ƭ **ProofPayload**: [`ProofInputPayload`](API.md#proofinputpayload) & { `iat`: `number`  }

#### Defined in

[src/ts/types.ts:111](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/types.ts#L111)

___

### SigningAlg

Ƭ **SigningAlg**: ``"RS256"`` \| ``"ES256"`` \| ``"ES512"`` \| ``"PS256"``

#### Defined in

[src/ts/types.ts:6](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/types.ts#L6)

## Functions

### createProof

▸ **createProof**(`payload`, `privateJwk`): `Promise`<`string`\>

Creates a non-repudiable proof for a given data exchange

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `payload` | [`ProofInputPayload`](API.md#proofinputpayload) | the payload to be added to the proof.                  `payload.iss` must be either the origin 'orig' or the destination 'dest' of the data exchange                  `payload.iat` should be ommitted since it will be automatically added when signing (`Date.now()`) |
| `privateJwk` | [`JWK`](interfaces/JWK.md) | The private key in JWK that will sign the proof |

#### Returns

`Promise`<`string`\>

a proof as a compact JWS formatted JWT string

#### Defined in

[src/ts/createProof.ts:16](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/createProof.ts#L16)

___

### jweDecrypt

▸ **jweDecrypt**(`jwe`, `secret`, `encAlg?`): `Promise`<[`CompactDecryptResult`](interfaces/CompactDecryptResult.md)\>

Decrypts jwe

#### Parameters

| Name | Type | Default value | Description |
| :------ | :------ | :------ | :------ |
| `jwe` | `string` | `undefined` | a JWE |
| `secret` | [`JWK`](interfaces/JWK.md) | `undefined` | a JWK with the secret to decrypt this jwe |
| `encAlg` | [`EncryptionAlg`](API.md#encryptionalg) | `'A256GCM'` | the algorithm for encryption |

#### Returns

`Promise`<[`CompactDecryptResult`](interfaces/CompactDecryptResult.md)\>

the plaintext

#### Defined in

[src/ts/jwe.ts:30](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/jwe.ts#L30)

___

### jweEncrypt

▸ **jweEncrypt**(`exchangeId`, `block`, `secret`, `encAlg`): `Promise`<`string`\>

Encrypts block to JWE

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `exchangeId` | `string` | the id of the data exchange |
| `block` | `Uint8Array` | the actual block of data |
| `secret` | [`JWK`](interfaces/JWK.md) | a one-time secret for encrypting this block |
| `encAlg` | [`EncryptionAlg`](API.md#encryptionalg) | the algorithm for encryption |

#### Returns

`Promise`<`string`\>

a Compact JWE

#### Defined in

[src/ts/jwe.ts:15](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/jwe.ts#L15)

___

### oneTimeSecret

▸ **oneTimeSecret**(`encAlg`): `Promise`<`Exclude`<[`Block`](interfaces/Block.md)[``"secret"``], `undefined`\>\>

Create a random (high entropy) symmetric secret for AES-256-GCM

#### Parameters

| Name | Type |
| :------ | :------ |
| `encAlg` | [`EncryptionAlg`](API.md#encryptionalg) |

#### Returns

`Promise`<`Exclude`<[`Block`](interfaces/Block.md)[``"secret"``], `undefined`\>\>

a promise that resolves to the secret in JWK and raw hex string

#### Defined in

[src/ts/oneTimeSecret.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/oneTimeSecret.ts#L12)

___

### sha

▸ **sha**(`input`, `algorithm`): `Promise`<`string`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `input` | `string` \| `Uint8Array` |
| `algorithm` | [`HashAlg`](API.md#hashalg) |

#### Returns

`Promise`<`string`\>

#### Defined in

[src/ts/sha.ts:3](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/sha.ts#L3)

___

### verifyKeyPair

▸ **verifyKeyPair**(`pubJWK`, `privJWK`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `pubJWK` | [`JWK`](interfaces/JWK.md) |
| `privJWK` | [`JWK`](interfaces/JWK.md) |

#### Returns

`Promise`<`void`\>

#### Defined in

[src/ts/verifyKeyPair.ts:4](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/verifyKeyPair.ts#L4)

___

### verifyProof

▸ **verifyProof**(`proof`, `publicJwk`, `expectedPayloadClaims`, `dateTolerance?`): `Promise`<[`JWTVerifyResult`](interfaces/JWTVerifyResult.md)\>

Verify a proof

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `proof` | `string` | a non-repudiable proof in Compact JWS formatted JWT string |
| `publicJwk` | [`JWK`](interfaces/JWK.md) | the publicKey as a JWK to use for verifying the signature. If MUST match either orig or dest (the one pointed on the iss field) |
| `expectedPayloadClaims` | [`ProofInputPayload`](API.md#proofinputpayload) | The expected values of the proof's payload claims. An expected value of '' can be use to just check that the claim is in the payload. An example could be: {   proofType: 'PoO',   iss: 'orig',   exchange: {     id: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',     orig: '{"kty":"EC","x":"rPMP39e-o8cU6m4WL8_qd2wxo-nBTjWXZtPGBiiGCTY","y":"0uvxGEebFDxKOHYUlHREzq4mRULuZvQ6LB2I11yE1E0","crv":"P-256"}', // Public key in JSON.stringify(JWK) of the block origin (sender)     dest: '{"kty":"EC","x":"qf_mNdy57ia1vAq5QLpTPxJUCRhS2003-gL0nLcbXoA","y":"H_8YwSCKJhDbZv17YEgDfAiKTaQ8x0jpLYCC2myxAeY","crv":"P-256"}', // Public key in JSON.stringify(JWK) of the block destination (receiver)     hash_alg: 'SHA-256',     cipherblock_dgst: 'IBUIstf98_afbiuh7UaifkasytNih7as-Jah61ls9UI', // hash of the cipherblock in base64url with no padding     block_commitment: '', // hash of the plaintext block in base64url with no padding     secret_commitment: '' // hash of the secret that can be used to decrypt the block in base64url with no padding   } } |
| `dateTolerance?` | [`DateTolerance`](interfaces/DateTolerance.md) | specifies a time window to accept the proof. An example could be {   currentDate: new Date('2021-10-17T03:24:00'), // Date to use when comparing NumericDate claims, defaults to new Date().   clockTolerance: 10  // string\|number Expected clock tolerance in seconds when number (e.g. 5), or parsed as seconds when a string (e.g. "5 seconds", "10 minutes", "2 hours") } |

#### Returns

`Promise`<[`JWTVerifyResult`](interfaces/JWTVerifyResult.md)\>

The JWT protected header and payload if the proof is validated

#### Defined in

[src/ts/verifyProof.ts:36](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/64711e2/src/ts/verifyProof.ts#L36)
