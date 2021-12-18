# Class: EthersSigner

[Signers](../modules/Signers.md).EthersSigner

A ledger signer using an ethers.io Wallet.

## Implements

- [`DltSigner`](Signers.DltSigner.md)

## Table of contents

### Constructors

- [constructor](Signers.EthersSigner.md#constructor)

### Properties

- [signer](Signers.EthersSigner.md#signer)

### Methods

- [signTransaction](Signers.EthersSigner.md#signtransaction)

## Constructors

### constructor

• **new EthersSigner**(`provider`, `privateKey`)

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `provider` | `Provider` |  |
| `privateKey` | `string` \| `Uint8Array` | the private key as an hexadecimal string ot Uint8Array |

#### Defined in

[src/ts/signers/EthersSigner.ts:18](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee76e40/src/ts/signers/EthersSigner.ts#L18)

## Properties

### signer

• **signer**: `Wallet`

#### Defined in

[src/ts/signers/EthersSigner.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee76e40/src/ts/signers/EthersSigner.ts#L11)

## Methods

### signTransaction

▸ **signTransaction**(`transaction`): `Promise`<`string`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `transaction` | `TransactionRequest` |

#### Returns

`Promise`<`string`\>

#### Implementation of

DltSigner.signTransaction

#### Defined in

[src/ts/signers/EthersSigner.ts:24](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee76e40/src/ts/signers/EthersSigner.ts#L24)
