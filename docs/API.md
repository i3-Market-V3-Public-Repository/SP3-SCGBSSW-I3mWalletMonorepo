# @i3-market/non-repudiation-proofs

My module description. Please update with your module data.

**`remarks`** 
This module runs perfectly in node.js and browsers

## Table of contents

### Interfaces

- [account](interfaces/account.md)
- [poO](interfaces/poo.md)
- [poR](interfaces/por.md)

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

• `Const` **SIGNING\_ALG**: *ES256*= 'ES256'

Defined in: createProofs.ts:11

## Functions

### createBlockchainProof

▸ `Const`**createBlockchainProof**(`publicKey`: KeyLike, `poO`: *string*, `poR`: *string*, `jwk`: JWK): *Promise*<[*account*](interfaces/account.md)\>

Prepare block to be send to the Backplain API

#### Parameters:

Name | Type |
:------ | :------ |
`publicKey` | KeyLike |
`poO` | *string* |
`poR` | *string* |
`jwk` | JWK |

**Returns:** *Promise*<[*account*](interfaces/account.md)\>

Defined in: createProofs.ts:125

___

### createJwk

▸ `Const`**createJwk**(): *Promise*<JWK\>

Create random (high entropy)\none time symmetric JWK secret

**Returns:** *Promise*<JWK\>

a promise that resolves to a JWK

Defined in: createProofs.ts:65

___

### createPoO

▸ `Const`**createPoO**(`privateKey`: KeyLike, `block`: *string* \| ArrayBufferLike, `providerId`: *string*, `consumerId`: *string*, `exchangeId`: *number*, `blockId`: *number*, `jwk`: JWK): *Promise*<{ `cipherblock`: *string* ; `poO`: *string*  }\>

Create Proof of Origin and sign with Provider private key

#### Parameters:

Name | Type | Description |
:------ | :------ | :------ |
`privateKey` | KeyLike | private key of the signer/issuer   |
`block` | *string* \| ArrayBufferLike | the blocks asdfsdfsd   |
`providerId` | *string* |  |
`consumerId` | *string* |  |
`exchangeId` | *number* |  |
`blockId` | *number* |  |
`jwk` | JWK |  |

**Returns:** *Promise*<{ `cipherblock`: *string* ; `poO`: *string*  }\>

Defined in: createProofs.ts:28

___

### createPoR

▸ `Const`**createPoR**(`privateKey`: KeyLike, `poO`: *string*, `providerId`: *string*, `consumerId`: *string*, `exchangeId`: *number*): *Promise*<string\>

Create Proof of Receipt and sign with Consumer private key

#### Parameters:

Name | Type |
:------ | :------ |
`privateKey` | KeyLike |
`poO` | *string* |
`providerId` | *string* |
`consumerId` | *string* |
`exchangeId` | *number* |

**Returns:** *Promise*<string\>

Defined in: createProofs.ts:103

___

### decodePoo

▸ `Const`**decodePoo**(`publicKey`: KeyLike, `poO`: *string*): *Promise*<[*poO*](interfaces/poo.md)\>

Decode Proof of Origin with Provider public key

#### Parameters:

Name | Type |
:------ | :------ |
`publicKey` | KeyLike |
`poO` | *string* |

**Returns:** *Promise*<[*poO*](interfaces/poo.md)\>

Defined in: validateProofs.ts:57

___

### decodePor

▸ `Const`**decodePor**(`publicKey`: KeyLike, `poR`: *string*): *Promise*<[*poR*](interfaces/por.md)\>

Decode Proof of Reception with Consumer public key

#### Parameters:

Name | Type |
:------ | :------ |
`publicKey` | KeyLike |
`poR` | *string* |

**Returns:** *Promise*<[*poR*](interfaces/por.md)\>

Defined in: validateProofs.ts:30

___

### decryptCipherblock

▸ `Const`**decryptCipherblock**(`chiperblock`: *string*, `jwk`: JWK): *Promise*<string\>

Decrypt the cipherblock received

#### Parameters:

Name | Type |
:------ | :------ |
`chiperblock` | *string* |
`jwk` | JWK |

**Returns:** *Promise*<string\>

Defined in: validateProofs.ts:86

___

### sha

▸ `Const`**sha**(`input`: *string* \| *Uint8Array*, `algorithm?`: *string*): *Promise*<string\>

#### Parameters:

Name | Type | Default value |
:------ | :------ | :------ |
`input` | *string* \| *Uint8Array* | - |
`algorithm` | *string* | 'SHA-256' |

**Returns:** *Promise*<string\>

Defined in: sha.ts:1

___

### signProof

▸ `Const`**signProof**(`privateKey`: KeyLike, `proof`: *any*): *Promise*<string\>

Sign a proof with private key

#### Parameters:

Name | Type |
:------ | :------ |
`privateKey` | KeyLike |
`proof` | *any* |

**Returns:** *Promise*<string\>

Defined in: createProofs.ts:91

___

### validateCipherblock

▸ `Const`**validateCipherblock**(`publicKey`: KeyLike, `chiperblock`: *string*, `jwk`: JWK, `poO`: [*poO*](interfaces/poo.md)): *Promise*<boolean\>

Validate the cipherblock

#### Parameters:

Name | Type |
:------ | :------ |
`publicKey` | KeyLike |
`chiperblock` | *string* |
`jwk` | JWK |
`poO` | [*poO*](interfaces/poo.md) |

**Returns:** *Promise*<boolean\>

Defined in: validateProofs.ts:97

___

### validatePoO

▸ `Const`**validatePoO**(`publicKey`: KeyLike, `poO`: *string*, `cipherblock`: *string*): *Promise*<boolean\>

Validate Proof or Origin using the Consumer Public Key

#### Parameters:

Name | Type |
:------ | :------ |
`publicKey` | KeyLike |
`poO` | *string* |
`cipherblock` | *string* |

**Returns:** *Promise*<boolean\>

Defined in: validateProofs.ts:41

___

### validatePoP

▸ `Const`**validatePoP**(`publicKeyBackplain`: KeyLike, `publicKeyProvider`: KeyLike, `poP`: *string*, `jwk`: JWK, `poO`: *string*): *Promise*<boolean\>

Validate Proof of Publication using the Backplain Public Key

#### Parameters:

Name | Type |
:------ | :------ |
`publicKeyBackplain` | KeyLike |
`publicKeyProvider` | KeyLike |
`poP` | *string* |
`jwk` | JWK |
`poO` | *string* |

**Returns:** *Promise*<boolean\>

Defined in: validateProofs.ts:68

___

### validatePoR

▸ `Const`**validatePoR**(`publicKey`: KeyLike, `poR`: *string*, `poO`: *string*): *Promise*<boolean\>

Validate Proof or Request using the Provider Public Key

#### Parameters:

Name | Type |
:------ | :------ |
`publicKey` | KeyLike |
`poR` | *string* |
`poO` | *string* |

**Returns:** *Promise*<boolean\>

Defined in: validateProofs.ts:14
