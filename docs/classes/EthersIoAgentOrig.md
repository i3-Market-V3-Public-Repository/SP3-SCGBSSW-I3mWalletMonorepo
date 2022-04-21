# Class: EthersIoAgentOrig

A DLT agent for the NRP orig using ethers.io.

## Hierarchy

- `EthersIoAgent`

  ↳ **`EthersIoAgentOrig`**

## Implements

- [`NrpDltAgentOrig`](../interfaces/Signers.NrpDltAgentOrig.md)

## Table of contents

### Constructors

- [constructor](EthersIoAgentOrig.md#constructor)

### Properties

- [contract](EthersIoAgentOrig.md#contract)
- [count](EthersIoAgentOrig.md#count)
- [dltConfig](EthersIoAgentOrig.md#dltconfig)
- [provider](EthersIoAgentOrig.md#provider)
- [signer](EthersIoAgentOrig.md#signer)

### Methods

- [deploySecret](EthersIoAgentOrig.md#deploysecret)
- [getAddress](EthersIoAgentOrig.md#getaddress)
- [getContractAddress](EthersIoAgentOrig.md#getcontractaddress)
- [nextNonce](EthersIoAgentOrig.md#nextnonce)

## Constructors

### constructor

• **new EthersIoAgentOrig**(`dltConfig`, `privateKey?`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `dltConfig` | `Partial`<[`DltConfig`](../interfaces/DltConfig.md)\> & `Pick`<[`DltConfig`](../interfaces/DltConfig.md), ``"rpcProviderUrl"``\> |
| `privateKey?` | `string` \| `Uint8Array` |

#### Overrides

EthersIoAgent.constructor

#### Defined in

[src/ts/dlt/agents/orig/EthersIoAgentOrig.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/667e852/src/ts/dlt/agents/orig/EthersIoAgentOrig.ts#L22)

## Properties

### contract

• **contract**: `Contract`

#### Inherited from

EthersIoAgent.contract

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/667e852/src/ts/dlt/agents/EthersIoAgent.ts#L11)

___

### count

• **count**: `number` = `-1`

The nonce of the next transaction to send to the blockchain. It keep track also of tx sent to the DLT bu not yet published on the blockchain

#### Defined in

[src/ts/dlt/agents/orig/EthersIoAgentOrig.ts:20](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/667e852/src/ts/dlt/agents/orig/EthersIoAgentOrig.ts#L20)

___

### dltConfig

• **dltConfig**: [`DltConfig`](../interfaces/DltConfig.md)

#### Inherited from

EthersIoAgent.dltConfig

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/667e852/src/ts/dlt/agents/EthersIoAgent.ts#L10)

___

### provider

• **provider**: `Provider`

#### Inherited from

EthersIoAgent.provider

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/667e852/src/ts/dlt/agents/EthersIoAgent.ts#L12)

___

### signer

• **signer**: `Wallet`

#### Defined in

[src/ts/dlt/agents/orig/EthersIoAgentOrig.ts:15](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/667e852/src/ts/dlt/agents/orig/EthersIoAgentOrig.ts#L15)

## Methods

### deploySecret

▸ **deploySecret**(`secretHex`, `exchangeId`): `Promise`<`string`\>

Publish the secret for a given data exchange on the ledger.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `secretHex` | `string` | the secret in hexadecimal |
| `exchangeId` | `string` | the exchange id |

#### Returns

`Promise`<`string`\>

a receipt of the deployment. In Ethereum-like DLTs it contains the transaction hash, which can be used to track the transaction on the ledger, and the nonce of the transaction

#### Implementation of

[NrpDltAgentOrig](../interfaces/Signers.NrpDltAgentOrig.md).[deploySecret](../interfaces/Signers.NrpDltAgentOrig.md#deploysecret)

#### Defined in

[src/ts/dlt/agents/orig/EthersIoAgentOrig.ts:44](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/667e852/src/ts/dlt/agents/orig/EthersIoAgentOrig.ts#L44)

___

### getAddress

▸ **getAddress**(): `Promise`<`string`\>

Returns and identifier of the signer's account on the ledger. In Ethereum-like DLTs is the Ethereum address

#### Returns

`Promise`<`string`\>

#### Implementation of

[NrpDltAgentOrig](../interfaces/Signers.NrpDltAgentOrig.md).[getAddress](../interfaces/Signers.NrpDltAgentOrig.md#getaddress)

#### Defined in

[src/ts/dlt/agents/orig/EthersIoAgentOrig.ts:64](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/667e852/src/ts/dlt/agents/orig/EthersIoAgentOrig.ts#L64)

___

### getContractAddress

▸ **getContractAddress**(): `Promise`<`string`\>

Returns the address of the smart contract in use

#### Returns

`Promise`<`string`\>

#### Implementation of

[NrpDltAgentOrig](../interfaces/Signers.NrpDltAgentOrig.md).[getContractAddress](../interfaces/Signers.NrpDltAgentOrig.md#getcontractaddress)

#### Inherited from

EthersIoAgent.getContractAddress

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/667e852/src/ts/dlt/agents/EthersIoAgent.ts#L26)

___

### nextNonce

▸ **nextNonce**(): `Promise`<`number`\>

#### Returns

`Promise`<`number`\>

#### Defined in

[src/ts/dlt/agents/orig/EthersIoAgentOrig.ts:68](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/667e852/src/ts/dlt/agents/orig/EthersIoAgentOrig.ts#L68)
