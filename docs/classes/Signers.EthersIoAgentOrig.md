# Class: EthersIoAgentOrig

[Signers](../modules/Signers.md).EthersIoAgentOrig

A DLT agent for the NRP orig using ethers.io.

## Hierarchy

- `EthersIoAgent`

  ↳ **`EthersIoAgentOrig`**

## Implements

- [`NrpDltAgentOrig`](../interfaces/Signers.NrpDltAgentOrig.md)

## Table of contents

### Constructors

- [constructor](Signers.EthersIoAgentOrig.md#constructor)

### Properties

- [contract](Signers.EthersIoAgentOrig.md#contract)
- [count](Signers.EthersIoAgentOrig.md#count)
- [dltConfig](Signers.EthersIoAgentOrig.md#dltconfig)
- [initialized](Signers.EthersIoAgentOrig.md#initialized)
- [provider](Signers.EthersIoAgentOrig.md#provider)
- [signer](Signers.EthersIoAgentOrig.md#signer)

### Methods

- [deploySecret](Signers.EthersIoAgentOrig.md#deploysecret)
- [getAddress](Signers.EthersIoAgentOrig.md#getaddress)
- [getContractAddress](Signers.EthersIoAgentOrig.md#getcontractaddress)
- [nextNonce](Signers.EthersIoAgentOrig.md#nextnonce)

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

[src/ts/dlt/agents/orig/EthersIoAgentOrig.ts:21](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee2a0c1/src/ts/dlt/agents/orig/EthersIoAgentOrig.ts#L21)

## Properties

### contract

• **contract**: `Contract`

#### Inherited from

EthersIoAgent.contract

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee2a0c1/src/ts/dlt/agents/EthersIoAgent.ts#L11)

___

### count

• **count**: `number` = `-1`

The nonce of the next transaction to send to the blockchain. It keep track also of tx sent to the DLT bu not yet published on the blockchain

#### Defined in

[src/ts/dlt/agents/orig/EthersIoAgentOrig.ts:19](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee2a0c1/src/ts/dlt/agents/orig/EthersIoAgentOrig.ts#L19)

___

### dltConfig

• **dltConfig**: [`DltConfig`](../interfaces/DltConfig.md)

#### Inherited from

EthersIoAgent.dltConfig

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee2a0c1/src/ts/dlt/agents/EthersIoAgent.ts#L10)

___

### initialized

• **initialized**: `Promise`<`boolean`\>

#### Inherited from

EthersIoAgent.initialized

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee2a0c1/src/ts/dlt/agents/EthersIoAgent.ts#L13)

___

### provider

• **provider**: `Provider`

#### Inherited from

EthersIoAgent.provider

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee2a0c1/src/ts/dlt/agents/EthersIoAgent.ts#L12)

___

### signer

• **signer**: `Wallet`

#### Defined in

[src/ts/dlt/agents/orig/EthersIoAgentOrig.ts:14](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee2a0c1/src/ts/dlt/agents/orig/EthersIoAgentOrig.ts#L14)

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

NrpDltAgentOrig.deploySecret

#### Defined in

[src/ts/dlt/agents/orig/EthersIoAgentOrig.ts:43](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee2a0c1/src/ts/dlt/agents/orig/EthersIoAgentOrig.ts#L43)

___

### getAddress

▸ **getAddress**(): `Promise`<`string`\>

Returns and identifier of the signer's account on the ledger. In Ethereum-like DLTs is the Ethereum address

#### Returns

`Promise`<`string`\>

#### Implementation of

NrpDltAgentOrig.getAddress

#### Defined in

[src/ts/dlt/agents/orig/EthersIoAgentOrig.ts:59](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee2a0c1/src/ts/dlt/agents/orig/EthersIoAgentOrig.ts#L59)

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

[src/ts/dlt/agents/EthersIoAgent.ts:43](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee2a0c1/src/ts/dlt/agents/EthersIoAgent.ts#L43)

___

### nextNonce

▸ **nextNonce**(): `Promise`<`number`\>

Returns the next nonce to use after deploying

#### Returns

`Promise`<`number`\>

#### Implementation of

NrpDltAgentOrig.nextNonce

#### Defined in

[src/ts/dlt/agents/orig/EthersIoAgentOrig.ts:65](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/ee2a0c1/src/ts/dlt/agents/orig/EthersIoAgentOrig.ts#L65)
