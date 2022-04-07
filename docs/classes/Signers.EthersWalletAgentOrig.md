# Class: EthersWalletAgentOrig

[Signers](../modules/Signers.md).EthersWalletAgentOrig

A ledger signer using an ethers.io Wallet.

## Hierarchy

- `EthersWalletAgent`

  ↳ **`EthersWalletAgentOrig`**

## Implements

- [`WalletAgentOrig`](../interfaces/Signers.WalletAgentOrig.md)

## Table of contents

### Constructors

- [constructor](Signers.EthersWalletAgentOrig.md#constructor)

### Properties

- [contract](Signers.EthersWalletAgentOrig.md#contract)
- [count](Signers.EthersWalletAgentOrig.md#count)
- [dltConfig](Signers.EthersWalletAgentOrig.md#dltconfig)
- [provider](Signers.EthersWalletAgentOrig.md#provider)
- [signer](Signers.EthersWalletAgentOrig.md#signer)

### Methods

- [deploySecret](Signers.EthersWalletAgentOrig.md#deploysecret)
- [getAddress](Signers.EthersWalletAgentOrig.md#getaddress)
- [getContractAddress](Signers.EthersWalletAgentOrig.md#getcontractaddress)
- [nextNonce](Signers.EthersWalletAgentOrig.md#nextnonce)

## Constructors

### constructor

• **new EthersWalletAgentOrig**(`privateKey?`, `dltConfig?`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `privateKey?` | `string` \| `Uint8Array` |
| `dltConfig?` | `Partial`<[`DltConfig`](../interfaces/DltConfig.md)\> |

#### Overrides

EthersWalletAgent.constructor

#### Defined in

[src/ts/dlt/wallet-agents/orig/EthersWalletAgentOrig.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/6ca578f/src/ts/dlt/wallet-agents/orig/EthersWalletAgentOrig.ts#L22)

## Properties

### contract

• **contract**: `Contract`

#### Inherited from

EthersWalletAgent.contract

#### Defined in

[src/ts/dlt/wallet-agents/EthersWalletAgent.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/6ca578f/src/ts/dlt/wallet-agents/EthersWalletAgent.ts#L11)

___

### count

• **count**: `number` = `-1`

The nonce of the next transaction to send to the blockchain. It keep track also of tx sent to the DLT bu not yet published on the blockchain

#### Defined in

[src/ts/dlt/wallet-agents/orig/EthersWalletAgentOrig.ts:20](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/6ca578f/src/ts/dlt/wallet-agents/orig/EthersWalletAgentOrig.ts#L20)

___

### dltConfig

• **dltConfig**: [`DltConfig`](../interfaces/DltConfig.md)

#### Inherited from

EthersWalletAgent.dltConfig

#### Defined in

[src/ts/dlt/wallet-agents/EthersWalletAgent.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/6ca578f/src/ts/dlt/wallet-agents/EthersWalletAgent.ts#L10)

___

### provider

• **provider**: `Provider`

#### Inherited from

EthersWalletAgent.provider

#### Defined in

[src/ts/dlt/wallet-agents/EthersWalletAgent.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/6ca578f/src/ts/dlt/wallet-agents/EthersWalletAgent.ts#L12)

___

### signer

• **signer**: `Wallet`

#### Defined in

[src/ts/dlt/wallet-agents/orig/EthersWalletAgentOrig.ts:15](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/6ca578f/src/ts/dlt/wallet-agents/orig/EthersWalletAgentOrig.ts#L15)

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

[WalletAgentOrig](../interfaces/Signers.WalletAgentOrig.md).[deploySecret](../interfaces/Signers.WalletAgentOrig.md#deploysecret)

#### Defined in

[src/ts/dlt/wallet-agents/orig/EthersWalletAgentOrig.ts:44](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/6ca578f/src/ts/dlt/wallet-agents/orig/EthersWalletAgentOrig.ts#L44)

___

### getAddress

▸ **getAddress**(): `Promise`<`string`\>

Returns and identifier of the signer's account on the ledger. In Ethereum-like DLTs is the Ethereum address

#### Returns

`Promise`<`string`\>

#### Implementation of

[WalletAgentOrig](../interfaces/Signers.WalletAgentOrig.md).[getAddress](../interfaces/Signers.WalletAgentOrig.md#getaddress)

#### Defined in

[src/ts/dlt/wallet-agents/orig/EthersWalletAgentOrig.ts:64](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/6ca578f/src/ts/dlt/wallet-agents/orig/EthersWalletAgentOrig.ts#L64)

___

### getContractAddress

▸ **getContractAddress**(): `Promise`<`string`\>

Returns the address of the smart contract in use

#### Returns

`Promise`<`string`\>

#### Implementation of

[WalletAgentOrig](../interfaces/Signers.WalletAgentOrig.md).[getContractAddress](../interfaces/Signers.WalletAgentOrig.md#getcontractaddress)

#### Inherited from

EthersWalletAgent.getContractAddress

#### Defined in

[src/ts/dlt/wallet-agents/EthersWalletAgent.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/6ca578f/src/ts/dlt/wallet-agents/EthersWalletAgent.ts#L26)

___

### nextNonce

▸ **nextNonce**(): `Promise`<`number`\>

#### Returns

`Promise`<`number`\>

#### Defined in

[src/ts/dlt/wallet-agents/orig/EthersWalletAgentOrig.ts:68](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/6ca578f/src/ts/dlt/wallet-agents/orig/EthersWalletAgentOrig.ts#L68)
