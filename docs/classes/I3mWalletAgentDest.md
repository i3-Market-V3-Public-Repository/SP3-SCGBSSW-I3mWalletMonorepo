# Class: I3mWalletAgentDest

A DLT agent for the NRP dest using ethers.io.

## Hierarchy

- [`EthersIoAgentDest`](Signers.EthersIoAgentDest.md)

  ↳ **`I3mWalletAgentDest`**

## Table of contents

### Constructors

- [constructor](I3mWalletAgentDest.md#constructor)

### Properties

- [contract](I3mWalletAgentDest.md#contract)
- [dltConfig](I3mWalletAgentDest.md#dltconfig)
- [provider](I3mWalletAgentDest.md#provider)

### Methods

- [getContractAddress](I3mWalletAgentDest.md#getcontractaddress)
- [getSecretFromLedger](I3mWalletAgentDest.md#getsecretfromledger)

## Constructors

### constructor

• **new I3mWalletAgentDest**(`dltConfig`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `dltConfig` | `Partial`<[`DltConfig`](../interfaces/DltConfig.md)\> & `Pick`<[`DltConfig`](../interfaces/DltConfig.md), ``"rpcProviderUrl"``\> |

#### Inherited from

[EthersIoAgentDest](Signers.EthersIoAgentDest.md).[constructor](Signers.EthersIoAgentDest.md#constructor)

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:14](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/59d622a/src/ts/dlt/agents/EthersIoAgent.ts#L14)

## Properties

### contract

• **contract**: `Contract`

#### Inherited from

[EthersIoAgentDest](Signers.EthersIoAgentDest.md).[contract](Signers.EthersIoAgentDest.md#contract)

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/59d622a/src/ts/dlt/agents/EthersIoAgent.ts#L11)

___

### dltConfig

• **dltConfig**: [`DltConfig`](../interfaces/DltConfig.md)

#### Inherited from

[EthersIoAgentDest](Signers.EthersIoAgentDest.md).[dltConfig](Signers.EthersIoAgentDest.md#dltconfig)

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/59d622a/src/ts/dlt/agents/EthersIoAgent.ts#L10)

___

### provider

• **provider**: `Provider`

#### Inherited from

[EthersIoAgentDest](Signers.EthersIoAgentDest.md).[provider](Signers.EthersIoAgentDest.md#provider)

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/59d622a/src/ts/dlt/agents/EthersIoAgent.ts#L12)

## Methods

### getContractAddress

▸ **getContractAddress**(): `Promise`<`string`\>

Returns the address of the smart contract in use

#### Returns

`Promise`<`string`\>

#### Inherited from

[EthersIoAgentDest](Signers.EthersIoAgentDest.md).[getContractAddress](Signers.EthersIoAgentDest.md#getcontractaddress)

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/59d622a/src/ts/dlt/agents/EthersIoAgent.ts#L26)

___

### getSecretFromLedger

▸ **getSecretFromLedger**(`signerAddress`, `exchangeId`, `timeout`): `Promise`<{ `hex`: `string` ; `iat`: `number`  }\>

Just in case the PoP is not received, the secret can be downloaded from the ledger.
The secret should be downloaded before poo.iat + pooToPop max delay.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `signerAddress` | `string` | the address (hexadecimal) of the entity publishing the secret. |
| `exchangeId` | `string` | the id of the data exchange |
| `timeout` | `number` | the timeout in seconds for waiting for the secret to be published on the ledger |

#### Returns

`Promise`<{ `hex`: `string` ; `iat`: `number`  }\>

the secret in hex and when it was published to the blockchain as a NumericDate

#### Inherited from

[EthersIoAgentDest](Signers.EthersIoAgentDest.md).[getSecretFromLedger](Signers.EthersIoAgentDest.md#getsecretfromledger)

#### Defined in

[src/ts/dlt/agents/dest/EthersIoAgentDest.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/59d622a/src/ts/dlt/agents/dest/EthersIoAgentDest.ts#L13)
