# Class: DltSigner

[Signers](../modules/Signers.md).DltSigner

An abstract class that should be implemeneted by any signer for the ledger.
A SW-based ethers.io Walllet is provided (EthersSigner) as a reference implementation

## Implemented by

- [`EthersSigner`](Signers.EthersSigner.md)

## Table of contents

### Constructors

- [constructor](Signers.DltSigner.md#constructor)

### Methods

- [signTransaction](Signers.DltSigner.md#signtransaction)

## Constructors

### constructor

• **new DltSigner**()

## Methods

### signTransaction

▸ **signTransaction**(`transaction`): `Promise`<`string`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `transaction` | `Object` |

#### Returns

`Promise`<`string`\>

#### Defined in

[src/ts/signers/Signer.ts:7](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/c516486/src/ts/signers/Signer.ts#L7)
