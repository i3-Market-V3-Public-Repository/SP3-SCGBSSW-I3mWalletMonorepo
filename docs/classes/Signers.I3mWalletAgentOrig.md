# Class: I3mWalletAgentOrig

[Signers](../modules/Signers.md).I3mWalletAgentOrig

## Hierarchy

- `I3mWalletAgent`

  ↳ **`I3mWalletAgentOrig`**

## Implements

- [`WalletAgentOrig`](../interfaces/Signers.WalletAgentOrig.md)

## Table of contents

### Constructors

- [constructor](Signers.I3mWalletAgentOrig.md#constructor)

### Properties

- [contract](Signers.I3mWalletAgentOrig.md#contract)
- [did](Signers.I3mWalletAgentOrig.md#did)
- [dltConfig](Signers.I3mWalletAgentOrig.md#dltconfig)
- [provider](Signers.I3mWalletAgentOrig.md#provider)
- [session](Signers.I3mWalletAgentOrig.md#session)

### Methods

- [deploySecret](Signers.I3mWalletAgentOrig.md#deploysecret)
- [getAddress](Signers.I3mWalletAgentOrig.md#getaddress)
- [getContractAddress](Signers.I3mWalletAgentOrig.md#getcontractaddress)

## Constructors

### constructor

• **new I3mWalletAgentOrig**(`session`, `did`, `dltConfig?`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `session` | `Session`<`HttpInitiatorTransport`\> |
| `did` | `string` |
| `dltConfig?` | `Partial`<[`DltConfig`](../interfaces/DltConfig.md)\> |

#### Inherited from

I3mWalletAgent.constructor

#### Defined in

[src/ts/dlt/wallet-agents/I3mWalletAgent.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/05d8d70/src/ts/dlt/wallet-agents/I3mWalletAgent.ts#L9)

## Properties

### contract

• **contract**: `Contract`

#### Inherited from

I3mWalletAgent.contract

#### Defined in

[src/ts/dlt/wallet-agents/EthersWalletAgent.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/05d8d70/src/ts/dlt/wallet-agents/EthersWalletAgent.ts#L11)

___

### did

• **did**: `string`

#### Inherited from

I3mWalletAgent.did

#### Defined in

[src/ts/dlt/wallet-agents/I3mWalletAgent.ts:7](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/05d8d70/src/ts/dlt/wallet-agents/I3mWalletAgent.ts#L7)

___

### dltConfig

• **dltConfig**: [`DltConfig`](../interfaces/DltConfig.md)

#### Inherited from

I3mWalletAgent.dltConfig

#### Defined in

[src/ts/dlt/wallet-agents/EthersWalletAgent.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/05d8d70/src/ts/dlt/wallet-agents/EthersWalletAgent.ts#L10)

___

### provider

• **provider**: `Provider`

#### Inherited from

I3mWalletAgent.provider

#### Defined in

[src/ts/dlt/wallet-agents/EthersWalletAgent.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/05d8d70/src/ts/dlt/wallet-agents/EthersWalletAgent.ts#L12)

___

### session

• **session**: `Session`<`HttpInitiatorTransport`\>

#### Inherited from

I3mWalletAgent.session

#### Defined in

[src/ts/dlt/wallet-agents/I3mWalletAgent.ts:6](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/05d8d70/src/ts/dlt/wallet-agents/I3mWalletAgent.ts#L6)

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

[WalletAgentOrig](../interfaces/Signers.WalletAgentOrig.md).[deploySecret](../interfaces/Signers.WalletAgentOrig.md#deploysecret)

#### Defined in

[src/ts/dlt/wallet-agents/orig/I3mWalletAgentOrig.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/05d8d70/src/ts/dlt/wallet-agents/orig/I3mWalletAgentOrig.ts#L9)

___

### getAddress

▸ **getAddress**(): `Promise`<`string`\>

Returns and identifier of the signer's account on the ledger. In Ethereum-like DLTs is the Ethereum address

#### Returns

`Promise`<`string`\>

#### Implementation of

[WalletAgentOrig](../interfaces/Signers.WalletAgentOrig.md).[getAddress](../interfaces/Signers.WalletAgentOrig.md#getaddress)

#### Defined in

[src/ts/dlt/wallet-agents/orig/I3mWalletAgentOrig.ts:47](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/05d8d70/src/ts/dlt/wallet-agents/orig/I3mWalletAgentOrig.ts#L47)

___

### getContractAddress

▸ **getContractAddress**(): `Promise`<`string`\>

Returns the address of the smart contract in use

#### Returns

`Promise`<`string`\>

#### Implementation of

[WalletAgentOrig](../interfaces/Signers.WalletAgentOrig.md).[getContractAddress](../interfaces/Signers.WalletAgentOrig.md#getcontractaddress)

#### Inherited from

I3mWalletAgent.getContractAddress

#### Defined in

[src/ts/dlt/wallet-agents/EthersWalletAgent.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/05d8d70/src/ts/dlt/wallet-agents/EthersWalletAgent.ts#L26)
