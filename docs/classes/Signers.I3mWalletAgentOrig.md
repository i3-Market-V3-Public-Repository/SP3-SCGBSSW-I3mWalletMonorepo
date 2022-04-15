# Class: I3mWalletAgentOrig

[Signers](../modules/Signers.md).I3mWalletAgentOrig

A DLT agent for the NRP orig using ethers.io library and the i3m-wallet for signing transactions to the DLT

## Hierarchy

- `I3mWalletAgent`

  ↳ **`I3mWalletAgentOrig`**

## Implements

- [`NrpDltAgentOrig`](../interfaces/Signers.NrpDltAgentOrig.md)

## Table of contents

### Constructors

- [constructor](Signers.I3mWalletAgentOrig.md#constructor)

### Properties

- [contract](Signers.I3mWalletAgentOrig.md#contract)
- [count](Signers.I3mWalletAgentOrig.md#count)
- [did](Signers.I3mWalletAgentOrig.md#did)
- [dltConfig](Signers.I3mWalletAgentOrig.md#dltconfig)
- [provider](Signers.I3mWalletAgentOrig.md#provider)
- [session](Signers.I3mWalletAgentOrig.md#session)

### Methods

- [deploySecret](Signers.I3mWalletAgentOrig.md#deploysecret)
- [getAddress](Signers.I3mWalletAgentOrig.md#getaddress)
- [getContractAddress](Signers.I3mWalletAgentOrig.md#getcontractaddress)
- [nextNonce](Signers.I3mWalletAgentOrig.md#nextnonce)

## Constructors

### constructor

• **new I3mWalletAgentOrig**(`session`, `did`, `dltConfig`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `session` | `Session`<`HttpInitiatorTransport`\> |
| `did` | `string` |
| `dltConfig` | `Partial`<[`DltConfig`](../interfaces/DltConfig.md)\> & `Pick`<[`DltConfig`](../interfaces/DltConfig.md), ``"rpcProviderUrl"``\> |

#### Inherited from

I3mWalletAgent.constructor

#### Defined in

src/ts/dlt/agents/I3mWalletAgent.ts:12

## Properties

### contract

• **contract**: `Contract`

#### Inherited from

I3mWalletAgent.contract

#### Defined in

src/ts/dlt/agents/EthersIoAgent.ts:11

___

### count

• **count**: `number` = `-1`

The nonce of the next transaction to send to the blockchain. It keep track also of tx sent to the DLT bu not yet published on the blockchain

#### Defined in

src/ts/dlt/agents/orig/I3mWalletAgentOrig.ts:15

___

### did

• **did**: `string`

#### Inherited from

I3mWalletAgent.did

#### Defined in

src/ts/dlt/agents/I3mWalletAgent.ts:10

___

### dltConfig

• **dltConfig**: [`DltConfig`](../interfaces/DltConfig.md)

#### Inherited from

I3mWalletAgent.dltConfig

#### Defined in

src/ts/dlt/agents/EthersIoAgent.ts:10

___

### provider

• **provider**: `Provider`

#### Inherited from

I3mWalletAgent.provider

#### Defined in

src/ts/dlt/agents/EthersIoAgent.ts:12

___

### session

• **session**: `Session`<`HttpInitiatorTransport`\>

#### Inherited from

I3mWalletAgent.session

#### Defined in

src/ts/dlt/agents/I3mWalletAgent.ts:9

## Methods

### deploySecret

▸ **deploySecret**(`secretHex`, `exchangeId`): `Promise`<`string`\>

Publish the secret for a given data exchange on the ledger.

#### Parameters

| Name | Type |
| :------ | :------ |
| `secretHex` | `string` |
| `exchangeId` | `string` |

#### Returns

`Promise`<`string`\>

#### Implementation of

[NrpDltAgentOrig](../interfaces/Signers.NrpDltAgentOrig.md).[deploySecret](../interfaces/Signers.NrpDltAgentOrig.md#deploysecret)

#### Defined in

src/ts/dlt/agents/orig/I3mWalletAgentOrig.ts:17

___

### getAddress

▸ **getAddress**(): `Promise`<`string`\>

Returns and identifier of the signer's account on the ledger. In Ethereum-like DLTs is the Ethereum address

#### Returns

`Promise`<`string`\>

#### Implementation of

[NrpDltAgentOrig](../interfaces/Signers.NrpDltAgentOrig.md).[getAddress](../interfaces/Signers.NrpDltAgentOrig.md#getaddress)

#### Defined in

src/ts/dlt/agents/orig/I3mWalletAgentOrig.ts:56

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

src/ts/dlt/agents/EthersIoAgent.ts:26

___

### nextNonce

▸ **nextNonce**(): `Promise`<`number`\>

#### Returns

`Promise`<`number`\>

#### Defined in

src/ts/dlt/agents/orig/I3mWalletAgentOrig.ts:67