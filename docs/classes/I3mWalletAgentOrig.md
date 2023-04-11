# Class: I3mWalletAgentOrig

A DLT agent for the NRP orig using ethers.io library and the i3m-wallet for signing transactions to the DLT

## Hierarchy

- `I3mWalletAgent`

  ↳ **`I3mWalletAgentOrig`**

## Implements

- [`NrpDltAgentOrig`](../interfaces/Signers.NrpDltAgentOrig.md)

## Table of contents

### Constructors

- [constructor](I3mWalletAgentOrig.md#constructor)

### Properties

- [contract](I3mWalletAgentOrig.md#contract)
- [count](I3mWalletAgentOrig.md#count)
- [did](I3mWalletAgentOrig.md#did)
- [dltConfig](I3mWalletAgentOrig.md#dltconfig)
- [initialized](I3mWalletAgentOrig.md#initialized)
- [provider](I3mWalletAgentOrig.md#provider)
- [wallet](I3mWalletAgentOrig.md#wallet)

### Methods

- [deploySecret](I3mWalletAgentOrig.md#deploysecret)
- [getAddress](I3mWalletAgentOrig.md#getaddress)
- [getContractAddress](I3mWalletAgentOrig.md#getcontractaddress)
- [nextNonce](I3mWalletAgentOrig.md#nextnonce)

## Constructors

### constructor

• **new I3mWalletAgentOrig**(`wallet`, `did`, `dltConfig?`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `wallet` | `WalletApi` |
| `did` | `string` |
| `dltConfig?` | `Partial`<`Omit`<[`DltConfig`](../interfaces/DltConfig.md), ``"rpcProviderUrl"``\>\> |

#### Inherited from

I3mWalletAgent.constructor

#### Defined in

[src/ts/dlt/agents/I3mWalletAgent.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/438f424/src/ts/dlt/agents/I3mWalletAgent.ts#L12)

## Properties

### contract

• **contract**: `Contract`

#### Inherited from

I3mWalletAgent.contract

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/438f424/src/ts/dlt/agents/EthersIoAgent.ts#L11)

___

### count

• **count**: `number` = `-1`

The nonce of the next transaction to send to the blockchain. It keep track also of tx sent to the DLT bu not yet published on the blockchain

#### Defined in

[src/ts/dlt/agents/orig/I3mWalletAgentOrig.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/438f424/src/ts/dlt/agents/orig/I3mWalletAgentOrig.ts#L13)

___

### did

• **did**: `string`

#### Inherited from

I3mWalletAgent.did

#### Defined in

[src/ts/dlt/agents/I3mWalletAgent.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/438f424/src/ts/dlt/agents/I3mWalletAgent.ts#L10)

___

### dltConfig

• **dltConfig**: [`DltConfig`](../interfaces/DltConfig.md)

#### Inherited from

I3mWalletAgent.dltConfig

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/438f424/src/ts/dlt/agents/EthersIoAgent.ts#L10)

___

### initialized

• **initialized**: `Promise`<`boolean`\>

#### Inherited from

I3mWalletAgent.initialized

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/438f424/src/ts/dlt/agents/EthersIoAgent.ts#L13)

___

### provider

• **provider**: `Provider`

#### Inherited from

I3mWalletAgent.provider

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/438f424/src/ts/dlt/agents/EthersIoAgent.ts#L12)

___

### wallet

• **wallet**: `WalletApi`

#### Inherited from

I3mWalletAgent.wallet

#### Defined in

[src/ts/dlt/agents/I3mWalletAgent.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/438f424/src/ts/dlt/agents/I3mWalletAgent.ts#L9)

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

a receipt of the deployment. In Ethereum-like DLTs it contains the transaction hash, which can be used to track the transaction on the ledger

#### Implementation of

NrpDltAgentOrig.deploySecret

#### Defined in

[src/ts/dlt/agents/orig/I3mWalletAgentOrig.ts:15](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/438f424/src/ts/dlt/agents/orig/I3mWalletAgentOrig.ts#L15)

___

### getAddress

▸ **getAddress**(): `Promise`<`string`\>

Returns and identifier of the signer's account on the ledger. In Ethereum-like DLTs is the Ethereum address

#### Returns

`Promise`<`string`\>

#### Implementation of

NrpDltAgentOrig.getAddress

#### Defined in

[src/ts/dlt/agents/orig/I3mWalletAgentOrig.ts:36](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/438f424/src/ts/dlt/agents/orig/I3mWalletAgentOrig.ts#L36)

___

### getContractAddress

▸ **getContractAddress**(): `Promise`<`string`\>

Returns the address of the smart contract in use

#### Returns

`Promise`<`string`\>

#### Implementation of

[NrpDltAgentOrig](../interfaces/Signers.NrpDltAgentOrig.md).[getContractAddress](../interfaces/Signers.NrpDltAgentOrig.md#getcontractaddress)

#### Inherited from

I3mWalletAgent.getContractAddress

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:43](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/438f424/src/ts/dlt/agents/EthersIoAgent.ts#L43)

___

### nextNonce

▸ **nextNonce**(): `Promise`<`number`\>

Returns the next nonce to use after deploying

#### Returns

`Promise`<`number`\>

#### Implementation of

NrpDltAgentOrig.nextNonce

#### Defined in

[src/ts/dlt/agents/orig/I3mWalletAgentOrig.ts:46](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/438f424/src/ts/dlt/agents/orig/I3mWalletAgentOrig.ts#L46)
