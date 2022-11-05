# Class: I3mServerWalletAgentOrig

## Hierarchy

- `I3mServerWalletAgent`

  ↳ **`I3mServerWalletAgentOrig`**

## Implements

- [`NrpDltAgentOrig`](../interfaces/Signers.NrpDltAgentOrig.md)

## Table of contents

### Constructors

- [constructor](I3mServerWalletAgentOrig.md#constructor)

### Properties

- [contract](I3mServerWalletAgentOrig.md#contract)
- [count](I3mServerWalletAgentOrig.md#count)
- [did](I3mServerWalletAgentOrig.md#did)
- [dltConfig](I3mServerWalletAgentOrig.md#dltconfig)
- [initialized](I3mServerWalletAgentOrig.md#initialized)
- [provider](I3mServerWalletAgentOrig.md#provider)
- [wallet](I3mServerWalletAgentOrig.md#wallet)

### Methods

- [deploySecret](I3mServerWalletAgentOrig.md#deploysecret)
- [getAddress](I3mServerWalletAgentOrig.md#getaddress)
- [getContractAddress](I3mServerWalletAgentOrig.md#getcontractaddress)
- [nextNonce](I3mServerWalletAgentOrig.md#nextnonce)

## Constructors

### constructor

• **new I3mServerWalletAgentOrig**(`serverWallet`, `did`, `dltConfig?`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `serverWallet` | `ServerWallet` |
| `did` | `string` |
| `dltConfig?` | `Partial`<`Omit`<[`DltConfig`](../interfaces/DltConfig.md), ``"rpcProviderUrk"``\>\> |

#### Inherited from

I3mServerWalletAgent.constructor

#### Defined in

[src/ts/dlt/agents/I3mServerWalletAgent.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/c2d8b20/src/ts/dlt/agents/I3mServerWalletAgent.ts#L12)

## Properties

### contract

• **contract**: `Contract`

#### Inherited from

I3mServerWalletAgent.contract

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/c2d8b20/src/ts/dlt/agents/EthersIoAgent.ts#L11)

___

### count

• **count**: `number` = `-1`

The nonce of the next transaction to send to the blockchain. It keep track also of tx sent to the DLT bu not yet published on the blockchain

#### Defined in

[src/ts/dlt/agents/orig/I3mServerWalletAgentOrig.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/c2d8b20/src/ts/dlt/agents/orig/I3mServerWalletAgentOrig.ts#L10)

___

### did

• **did**: `string`

#### Inherited from

I3mServerWalletAgent.did

#### Defined in

[src/ts/dlt/agents/I3mServerWalletAgent.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/c2d8b20/src/ts/dlt/agents/I3mServerWalletAgent.ts#L10)

___

### dltConfig

• **dltConfig**: [`DltConfig`](../interfaces/DltConfig.md)

#### Inherited from

I3mServerWalletAgent.dltConfig

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/c2d8b20/src/ts/dlt/agents/EthersIoAgent.ts#L10)

___

### initialized

• **initialized**: `Promise`<`boolean`\>

#### Inherited from

I3mServerWalletAgent.initialized

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/c2d8b20/src/ts/dlt/agents/EthersIoAgent.ts#L13)

___

### provider

• **provider**: `Provider`

#### Inherited from

I3mServerWalletAgent.provider

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/c2d8b20/src/ts/dlt/agents/EthersIoAgent.ts#L12)

___

### wallet

• **wallet**: `ServerWallet`

#### Inherited from

I3mServerWalletAgent.wallet

#### Defined in

[src/ts/dlt/agents/I3mServerWalletAgent.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/c2d8b20/src/ts/dlt/agents/I3mServerWalletAgent.ts#L9)

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

[src/ts/dlt/agents/orig/I3mServerWalletAgentOrig.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/c2d8b20/src/ts/dlt/agents/orig/I3mServerWalletAgentOrig.ts#L12)

___

### getAddress

▸ **getAddress**(): `Promise`<`string`\>

Returns and identifier of the signer's account on the ledger. In Ethereum-like DLTs is the Ethereum address

#### Returns

`Promise`<`string`\>

#### Implementation of

NrpDltAgentOrig.getAddress

#### Defined in

[src/ts/dlt/agents/orig/I3mServerWalletAgentOrig.ts:28](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/c2d8b20/src/ts/dlt/agents/orig/I3mServerWalletAgentOrig.ts#L28)

___

### getContractAddress

▸ **getContractAddress**(): `Promise`<`string`\>

Returns the address of the smart contract in use

#### Returns

`Promise`<`string`\>

#### Implementation of

[NrpDltAgentOrig](../interfaces/Signers.NrpDltAgentOrig.md).[getContractAddress](../interfaces/Signers.NrpDltAgentOrig.md#getcontractaddress)

#### Inherited from

I3mServerWalletAgent.getContractAddress

#### Defined in

[src/ts/dlt/agents/EthersIoAgent.ts:43](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/c2d8b20/src/ts/dlt/agents/EthersIoAgent.ts#L43)

___

### nextNonce

▸ **nextNonce**(): `Promise`<`number`\>

Returns the next nonce to use after deploying

#### Returns

`Promise`<`number`\>

#### Implementation of

NrpDltAgentOrig.nextNonce

#### Defined in

[src/ts/dlt/agents/orig/I3mServerWalletAgentOrig.ts:38](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/c2d8b20/src/ts/dlt/agents/orig/I3mServerWalletAgentOrig.ts#L38)
