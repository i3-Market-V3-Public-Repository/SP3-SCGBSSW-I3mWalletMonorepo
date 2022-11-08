# Class: I3mServerWalletAgentDest

[Signers](../modules/Signers.md).I3mServerWalletAgentDest

A DLT agent for the NRP dest using the i3-MARKET server Wallet.

## Hierarchy

- `I3mServerWalletAgent`

  ↳ **`I3mServerWalletAgentDest`**

## Implements

- [`NrpDltAgentDest`](../interfaces/Signers.NrpDltAgentDest.md)

## Table of contents

### Constructors

- [constructor](Signers.I3mServerWalletAgentDest.md#constructor)

### Properties

- [contract](Signers.I3mServerWalletAgentDest.md#contract)
- [did](Signers.I3mServerWalletAgentDest.md#did)
- [dltConfig](Signers.I3mServerWalletAgentDest.md#dltconfig)
- [initialized](Signers.I3mServerWalletAgentDest.md#initialized)
- [provider](Signers.I3mServerWalletAgentDest.md#provider)
- [wallet](Signers.I3mServerWalletAgentDest.md#wallet)

### Methods

- [getContractAddress](Signers.I3mServerWalletAgentDest.md#getcontractaddress)
- [getSecretFromLedger](Signers.I3mServerWalletAgentDest.md#getsecretfromledger)

## Constructors

### constructor

• **new I3mServerWalletAgentDest**(`serverWallet`, `did`, `dltConfig?`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `serverWallet` | `ServerWallet` |
| `did` | `string` |
| `dltConfig?` | `Partial`<`Omit`<[`DltConfig`](../interfaces/DltConfig.md), ``"rpcProviderUrk"``\>\> |

#### Inherited from

I3mServerWalletAgent.constructor

#### Defined in

[src/ts/dlt/agents/I3mServerWalletAgent.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/75b7c79/src/ts/dlt/agents/I3mServerWalletAgent.ts#L12)

## Properties

### contract

• **contract**: `Contract`

#### Inherited from

I3mServerWalletAgent.contract

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/75b7c79/src/ts/dlt/agents/EthersIoAgent.ts#L11)

___

### did

• **did**: `string`

#### Inherited from

I3mServerWalletAgent.did

#### Defined in

[src/ts/dlt/agents/I3mServerWalletAgent.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/75b7c79/src/ts/dlt/agents/I3mServerWalletAgent.ts#L10)

___

### dltConfig

• **dltConfig**: [`DltConfig`](../interfaces/DltConfig.md)

#### Inherited from

I3mServerWalletAgent.dltConfig

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/75b7c79/src/ts/dlt/agents/EthersIoAgent.ts#L10)

___

### initialized

• **initialized**: `Promise`<`boolean`\>

#### Inherited from

I3mServerWalletAgent.initialized

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/75b7c79/src/ts/dlt/agents/EthersIoAgent.ts#L13)

___

### provider

• **provider**: `Provider`

#### Inherited from

I3mServerWalletAgent.provider

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/75b7c79/src/ts/dlt/agents/EthersIoAgent.ts#L12)

___

### wallet

• **wallet**: `ServerWallet`

#### Inherited from

I3mServerWalletAgent.wallet

#### Defined in

[src/ts/dlt/agents/I3mServerWalletAgent.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/75b7c79/src/ts/dlt/agents/I3mServerWalletAgent.ts#L9)

## Methods

### getContractAddress

▸ **getContractAddress**(): `Promise`<`string`\>

Returns the address of the smart contract in use

#### Returns

`Promise`<`string`\>

#### Implementation of

[NrpDltAgentDest](../interfaces/Signers.NrpDltAgentDest.md).[getContractAddress](../interfaces/Signers.NrpDltAgentDest.md#getcontractaddress)

#### Inherited from

I3mServerWalletAgent.getContractAddress

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:43](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/75b7c79/src/ts/dlt/agents/EthersIoAgent.ts#L43)

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

#### Implementation of

NrpDltAgentDest.getSecretFromLedger

#### Defined in

[src/ts/dlt/agents/dest/I3mServerWalletAgentDest.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/75b7c79/src/ts/dlt/agents/dest/I3mServerWalletAgentDest.ts#L9)
