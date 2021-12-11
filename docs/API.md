# @i3m/non-repudiation-protocol - v1.0.1

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
- [DataExchangeAgreement](interfaces/DataExchangeAgreement.md)
- [DltConfig](interfaces/DltConfig.md)
- [JWK](interfaces/JWK.md)
- [JWTVerifyResult](interfaces/JWTVerifyResult.md)
- [JwkPair](interfaces/JwkPair.md)
- [OrigBlock](interfaces/OrigBlock.md)
- [PoOInputPayload](interfaces/PoOInputPayload.md)
- [PoOPayload](interfaces/PoOPayload.md)
- [PoPInputPayload](interfaces/PoPInputPayload.md)
- [PoPPayload](interfaces/PoPPayload.md)
- [PoRInputPayload](interfaces/PoRInputPayload.md)
- [PoRPayload](interfaces/PoRPayload.md)
- [ProofInputPayload](interfaces/ProofInputPayload.md)
- [ProofPayload](interfaces/ProofPayload.md)
- [StoredProof](interfaces/StoredProof.md)
- [TimestampVerifyOptions](interfaces/TimestampVerifyOptions.md)

### Type aliases

- [ContractInterface](API.md#contractinterface)
- [EncryptionAlg](API.md#encryptionalg)
- [HashAlg](API.md#hashalg)
- [SigningAlg](API.md#signingalg)

### Functions

- [createProof](API.md#createproof)
- [generateKeys](API.md#generatekeys)
- [jweDecrypt](API.md#jwedecrypt)
- [jweEncrypt](API.md#jweencrypt)
- [oneTimeSecret](API.md#onetimesecret)
- [parseHex](API.md#parsehex)
- [sha](API.md#sha)
- [verifyKeyPair](API.md#verifykeypair)
- [verifyProof](API.md#verifyproof)

## Type aliases

### ContractInterface

Ƭ **ContractInterface**: `string` \| `ReadonlyArray`<`Fragment` \| `JsonFragment` \| `string`\> \| `Interface`

#### Defined in

node_modules/@ethersproject/contracts/lib/index.d.ts:75

___

### EncryptionAlg

Ƭ **EncryptionAlg**: ``"A128GCM"`` \| ``"A256GCM"``

#### Defined in

[src/ts/types.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/6b80b00/src/ts/types.ts#L9)

___

### HashAlg

Ƭ **HashAlg**: ``"SHA-256"`` \| ``"SHA-384"`` \| ``"SHA-512"``

#### Defined in

[src/ts/types.ts:7](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/6b80b00/src/ts/types.ts#L7)

___

### SigningAlg

Ƭ **SigningAlg**: ``"ES256"`` \| ``"ES384"`` \| ``"ES512"``

#### Defined in

[src/ts/types.ts:8](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/6b80b00/src/ts/types.ts#L8)

## Functions

### createProof

▸ **createProof**(`payload`, `privateJwk`): `Promise`<[`StoredProof`](interfaces/StoredProof.md)\>

Creates a non-repudiable proof for a given data exchange

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `payload` | [`ProofInputPayload`](interfaces/ProofInputPayload.md) | the payload to be added to the proof.                  `payload.iss` must be either the origin 'orig' or the destination 'dest' of the data exchange                  `payload.iat` shall be ommitted since it will be automatically added when signing (`Date.now()`) |
| `privateJwk` | [`JWK`](interfaces/JWK.md) | The private key in JWK that will sign the proof |

#### Returns

`Promise`<[`StoredProof`](interfaces/StoredProof.md)\>

a proof as a compact JWS formatted JWT string

#### Defined in

[src/ts/createProof.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/6b80b00/src/ts/createProof.ts#L13)

___

### generateKeys

▸ **generateKeys**(`alg`, `privateKey?`, `base64?`): `Promise`<[`JwkPair`](interfaces/JwkPair.md)\>

Generates a pair of JWK signing/verification keys

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `alg` | [`SigningAlg`](API.md#signingalg) | the signing algorithm to use |
| `privateKey?` | `string` \| `Uint8Array` | an optional private key as a Uint8Array, or a string (hex or base64) |
| `base64?` | `boolean` | - |

#### Returns

`Promise`<[`JwkPair`](interfaces/JwkPair.md)\>

#### Defined in

[src/ts/generateKeys.ts:15](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/6b80b00/src/ts/generateKeys.ts#L15)

___

### jweDecrypt

▸ **jweDecrypt**(`jwe`, `secret`, `encAlg?`): `Promise`<[`CompactDecryptResult`](interfaces/CompactDecryptResult.md)\>

Decrypts jwe

#### Parameters

| Name | Type | Default value | Description |
| :------ | :------ | :------ | :------ |
| `jwe` | `string` | `undefined` | a JWE |
| `secret` | `JWK` | `undefined` | a JWK with the secret to decrypt this jwe |
| `encAlg` | [`EncryptionAlg`](API.md#encryptionalg) | `'A256GCM'` | the algorithm for encryption |

#### Returns

`Promise`<[`CompactDecryptResult`](interfaces/CompactDecryptResult.md)\>

the plaintext

#### Defined in

[src/ts/jwe.ts:28](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/6b80b00/src/ts/jwe.ts#L28)

___

### jweEncrypt

▸ **jweEncrypt**(`block`, `secret`, `encAlg`): `Promise`<`string`\>

Encrypts block to JWE

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `block` | `Uint8Array` | the actual block of data |
| `secret` | `JWK` | a one-time secret for encrypting this block |
| `encAlg` | [`EncryptionAlg`](API.md#encryptionalg) | the algorithm for encryption |

#### Returns

`Promise`<`string`\>

a Compact JWE

#### Defined in

[src/ts/jwe.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/6b80b00/src/ts/jwe.ts#L13)

___

### oneTimeSecret

▸ **oneTimeSecret**(`encAlg`, `secret?`, `base64?`): `Promise`<`Exclude`<[`Block`](interfaces/Block.md)[``"secret"``], `undefined`\>\>

Create a JWK random (high entropy) symmetric secret

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `encAlg` | [`EncryptionAlg`](API.md#encryptionalg) | the encryption algorithm |
| `secret?` | `string` \| `Uint8Array` | and optional seed as Uint8Array or string (hex or base64) |
| `base64?` | `boolean` | if a secret is provided as a string, sets base64 decoding. It supports standard, url-safe base64 with and without padding (autodetected). |

#### Returns

`Promise`<`Exclude`<[`Block`](interfaces/Block.md)[``"secret"``], `undefined`\>\>

a promise that resolves to the secret in JWK and raw hex string

#### Defined in

[src/ts/oneTimeSecret.ts:16](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/6b80b00/src/ts/oneTimeSecret.ts#L16)

___

### parseHex

▸ **parseHex**(`a`): `string`

#### Parameters

| Name | Type |
| :------ | :------ |
| `a` | `string` |

#### Returns

`string`

#### Defined in

[src/ts/utils.ts:1](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/6b80b00/src/ts/utils.ts#L1)

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

[src/ts/sha.ts:3](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/6b80b00/src/ts/sha.ts#L3)

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

[src/ts/verifyKeyPair.ts:5](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/6b80b00/src/ts/verifyKeyPair.ts#L5)

___

### verifyProof

▸ **verifyProof**(`proof`, `publicJwk`, `expectedPayloadClaims`, `timestampVerifyOptions?`): `Promise`<[`JWTVerifyResult`](interfaces/JWTVerifyResult.md)\>

Verify a proof

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `proof` | `string` | a non-repudiable proof in Compact JWS formatted JWT string |
| `publicJwk` | `JWK` | the publicKey as a JWK to use for verifying the signature. If MUST match either orig or dest (the one pointed on the iss field) |
| `expectedPayloadClaims` | [`ProofInputPayload`](interfaces/ProofInputPayload.md) | The expected values of the proof's payload claims. An expected value of '' can be use to just check that the claim is in the payload. An example could be: {   proofType: 'PoO',   iss: 'orig',   exchange: {     id: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',     orig: '{"kty":"EC","x":"rPMP39e-o8cU6m4WL8_qd2wxo-nBTjWXZtPGBiiGCTY","y":"0uvxGEebFDxKOHYUlHREzq4mRULuZvQ6LB2I11yE1E0","crv":"P-256"}', // Public key in JSON.stringify(JWK) of the block origin (sender)     dest: '{"kty":"EC","x":"qf_mNdy57ia1vAq5QLpTPxJUCRhS2003-gL0nLcbXoA","y":"H_8YwSCKJhDbZv17YEgDfAiKTaQ8x0jpLYCC2myxAeY","crv":"P-256"}', // Public key in JSON.stringify(JWK) of the block destination (receiver)     hash_alg: 'SHA-256',     cipherblock_dgst: 'IBUIstf98_afbiuh7UaifkasytNih7as-Jah61ls9UI', // hash of the cipherblock in base64url with no padding     block_commitment: '', // hash of the plaintext block in base64url with no padding     secret_commitment: '' // hash of the secret that can be used to decrypt the block in base64url with no padding   } } |
| `timestampVerifyOptions?` | [`TimestampVerifyOptions`](interfaces/TimestampVerifyOptions.md) | specifies a time window to accept the proof |

#### Returns

`Promise`<[`JWTVerifyResult`](interfaces/JWTVerifyResult.md)\>

The JWT protected header and payload if the proof is validated

#### Defined in

[src/ts/verifyProof.ts:31](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-protocol/-/blob/6b80b00/src/ts/verifyProof.ts#L31)
