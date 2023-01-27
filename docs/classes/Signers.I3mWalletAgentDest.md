# Class: I3mWalletAgentDest

[Signers](../modules/Signers.md).I3mWalletAgentDest

A DLT agent for the NRP dest using the i3M-Wallet

## Hierarchy

- `I3mWalletAgent`

  ↳ **`I3mWalletAgentDest`**

## Implements

- [`NrpDltAgentDest`](../interfaces/Signers.NrpDltAgentDest.md)

## Table of contents

### Constructors

- [constructor](Signers.I3mWalletAgentDest.md#constructor)

### Properties

- [contract](Signers.I3mWalletAgentDest.md#contract)
- [did](Signers.I3mWalletAgentDest.md#did)
- [dltConfig](Signers.I3mWalletAgentDest.md#dltconfig)
- [initialized](Signers.I3mWalletAgentDest.md#initialized)
- [provider](Signers.I3mWalletAgentDest.md#provider)
- [wallet](Signers.I3mWalletAgentDest.md#wallet)

### Methods

- [getContractAddress](Signers.I3mWalletAgentDest.md#getcontractaddress)
- [getSecretFromLedger](Signers.I3mWalletAgentDest.md#getsecretfromledger)

## Constructors

### constructor

• **new I3mWalletAgentDest**(`wallet`, `did`, `dltConfig?`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `wallet` | `WalletApi` |
| `did` | `string` |
| `dltConfig?` | `Partial`<`Omit`<[`DltConfig`](../interfaces/DltConfig.md), ``"rpcProviderUrk"``\>\> |

#### Inherited from

I3mWalletAgent.constructor

#### Defined in

[src/ts/dlt/agents/I3mWalletAgent.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/31fe7d0/src/ts/dlt/agents/I3mWalletAgent.ts#L12)

## Properties

### contract

• **contract**: `Contract`

#### Inherited from

I3mWalletAgent.contract

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/31fe7d0/src/ts/dlt/agents/EthersIoAgent.ts#L11)

___

### did

• **did**: `string`

#### Inherited from

I3mWalletAgent.did

#### Defined in

[src/ts/dlt/agents/I3mWalletAgent.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/31fe7d0/src/ts/dlt/agents/I3mWalletAgent.ts#L10)

___

### dltConfig

• **dltConfig**: [`DltConfig`](../interfaces/DltConfig.md)

#### Inherited from

I3mWalletAgent.dltConfig

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/31fe7d0/src/ts/dlt/agents/EthersIoAgent.ts#L10)

___

### initialized

• **initialized**: `Promise`<`boolean`\>

#### Inherited from

I3mWalletAgent.initialized

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/31fe7d0/src/ts/dlt/agents/EthersIoAgent.ts#L13)

___

### provider

• **provider**: `Provider`

#### Inherited from

I3mWalletAgent.provider

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/31fe7d0/src/ts/dlt/agents/EthersIoAgent.ts#L12)

___

### wallet

• **wallet**: `WalletApi`

#### Inherited from

I3mWalletAgent.wallet

#### Defined in

[src/ts/dlt/agents/I3mWalletAgent.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/31fe7d0/src/ts/dlt/agents/I3mWalletAgent.ts#L9)

## Methods

### getContractAddress

▸ **getContractAddress**(): `Promise`<`string`\>

Returns the address of the smart contract in use

#### Returns

`Promise`<`string`\>

#### Implementation of

[NrpDltAgentDest](../interfaces/Signers.NrpDltAgentDest.md).[getContractAddress](../interfaces/Signers.NrpDltAgentDest.md#getcontractaddress)

#### Inherited from

I3mWalletAgent.getContractAddress

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

[src/ts/dlt/agents/dest/I3mWalletAgentDest.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/31fe7d0/src/ts/dlt/agents/dest/I3mWalletAgentDest.ts#L9)
