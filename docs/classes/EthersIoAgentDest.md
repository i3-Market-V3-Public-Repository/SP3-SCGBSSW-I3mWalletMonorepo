# Class: EthersIoAgentDest

A DLT agent for the NRP dest using ethers.io.

## Hierarchy

- `EthersIoAgent`

  ↳ **`EthersIoAgentDest`**

## Implements

- [`NrpDltAgentDest`](../interfaces/Signers.NrpDltAgentDest.md)

## Table of contents

### Constructors

- [constructor](EthersIoAgentDest.md#constructor)

### Properties

- [contract](EthersIoAgentDest.md#contract)
- [dltConfig](EthersIoAgentDest.md#dltconfig)
- [initialized](EthersIoAgentDest.md#initialized)
- [provider](EthersIoAgentDest.md#provider)

### Methods

- [getContractAddress](EthersIoAgentDest.md#getcontractaddress)
- [getSecretFromLedger](EthersIoAgentDest.md#getsecretfromledger)

## Constructors

### constructor

• **new EthersIoAgentDest**(`dltConfig`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `dltConfig` | `Partial`<[`DltConfig`](../interfaces/DltConfig.md)\> & `Pick`<[`DltConfig`](../interfaces/DltConfig.md), ``"rpcProviderUrl"``\> \| `Promise`<`Partial`<[`DltConfig`](../interfaces/DltConfig.md)\> & `Pick`<[`DltConfig`](../interfaces/DltConfig.md), ``"rpcProviderUrl"``\>\> |

#### Inherited from

EthersIoAgent.constructor

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:15](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/31fe7d0/src/ts/dlt/agents/EthersIoAgent.ts#L15)

## Properties

### contract

• **contract**: `Contract`

#### Inherited from

EthersIoAgent.contract

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/31fe7d0/src/ts/dlt/agents/EthersIoAgent.ts#L11)

___

### dltConfig

• **dltConfig**: [`DltConfig`](../interfaces/DltConfig.md)

#### Inherited from

EthersIoAgent.dltConfig

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/31fe7d0/src/ts/dlt/agents/EthersIoAgent.ts#L10)

___

### initialized

• **initialized**: `Promise`<`boolean`\>

#### Inherited from

EthersIoAgent.initialized

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/31fe7d0/src/ts/dlt/agents/EthersIoAgent.ts#L13)

___

### provider

• **provider**: `Provider`

#### Inherited from

EthersIoAgent.provider

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/31fe7d0/src/ts/dlt/agents/EthersIoAgent.ts#L12)

## Methods

### getContractAddress

▸ **getContractAddress**(): `Promise`<`string`\>

Returns the address of the smart contract in use

#### Returns

`Promise`<`string`\>

#### Implementation of

[NrpDltAgentDest](../interfaces/Signers.NrpDltAgentDest.md).[getContractAddress](../interfaces/Signers.NrpDltAgentDest.md#getcontractaddress)

#### Inherited from

EthersIoAgent.getContractAddress

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:43](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/31fe7d0/src/ts/dlt/agents/EthersIoAgent.ts#L43)

___

### getSecretFromLedger

▸ **getSecretFromLedger**(`secretLength`, `signerAddress`, `exchangeId`, `timeout`): `Promise`<{ `hex`: `string` ; `iat`: `number`  }\>

Just in case the PoP is not received, the secret can be downloaded from the ledger.
The secret should be downloaded before poo.iat + pooToPop max delay.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `secretLength` | `number` | the expected length of the secret to get |
| `signerAddress` | `string` | the address (hexadecimal) of the entity publishing the secret. |
| `exchangeId` | `string` | the id of the data exchange |
| `timeout` | `number` | the timeout in seconds for waiting for the secret to be published on the ledger |

#### Returns

`Promise`<{ `hex`: `string` ; `iat`: `number`  }\>

the secret in hex and when it was published to the blockchain as a NumericDate

#### Implementation of

NrpDltAgentDest.getSecretFromLedger

#### Defined in

[src/ts/dlt/agents/dest/EthersIoAgentDest.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/31fe7d0/src/ts/dlt/agents/dest/EthersIoAgentDest.ts#L9)
