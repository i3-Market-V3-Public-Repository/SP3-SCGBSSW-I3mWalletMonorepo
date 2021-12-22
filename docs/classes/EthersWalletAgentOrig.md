# Class: EthersWalletAgentOrig

A ledger signer using an ethers.io Wallet.

## Hierarchy

- `EthersWalletAgent`

  ↳ **`EthersWalletAgentOrig`**

## Implements

- [`WalletAgentOrig`](../interfaces/Signers.WalletAgentOrig.md)

## Table of contents

### Constructors

- [constructor](EthersWalletAgentOrig.md#constructor)

### Properties

- [contract](EthersWalletAgentOrig.md#contract)
- [dltConfig](EthersWalletAgentOrig.md#dltconfig)
- [provider](EthersWalletAgentOrig.md#provider)
- [signer](EthersWalletAgentOrig.md#signer)

### Methods

- [deploySecret](EthersWalletAgentOrig.md#deploysecret)
- [getAddress](EthersWalletAgentOrig.md#getaddress)
- [getContractAddress](EthersWalletAgentOrig.md#getcontractaddress)

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

src/ts/dlt/wallet-agents/orig/EthersWalletAgentOrig.ts:17

## Properties

### contract

• **contract**: `Contract`

#### Inherited from

EthersWalletAgent.contract

#### Defined in

src/ts/dlt/wallet-agents/EthersWalletAgent.ts:11

___

### dltConfig

• **dltConfig**: [`DltConfig`](../interfaces/DltConfig.md)

#### Inherited from

EthersWalletAgent.dltConfig

#### Defined in

src/ts/dlt/wallet-agents/EthersWalletAgent.ts:10

___

### provider

• **provider**: `Provider`

#### Inherited from

EthersWalletAgent.provider

#### Defined in

src/ts/dlt/wallet-agents/EthersWalletAgent.ts:12

___

### signer

• **signer**: `Wallet`

#### Defined in

src/ts/dlt/wallet-agents/orig/EthersWalletAgentOrig.ts:15

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

a receipt of the deployment. In Ethereum-like DLTs it is the transaction hash, which can be used to track the transaction on the ledger

#### Implementation of

[WalletAgentOrig](../interfaces/Signers.WalletAgentOrig.md).[deploySecret](../interfaces/Signers.WalletAgentOrig.md#deploysecret)

#### Defined in

src/ts/dlt/wallet-agents/orig/EthersWalletAgentOrig.ts:39

___

### getAddress

▸ **getAddress**(): `Promise`<`string`\>

Returns and identifier of the signer's account on the ledger. In Ethereum-like DLTs is the Ethereum address

#### Returns

`Promise`<`string`\>

#### Implementation of

[WalletAgentOrig](../interfaces/Signers.WalletAgentOrig.md).[getAddress](../interfaces/Signers.WalletAgentOrig.md#getaddress)

#### Defined in

src/ts/dlt/wallet-agents/orig/EthersWalletAgentOrig.ts:57

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

src/ts/dlt/wallet-agents/EthersWalletAgent.ts:26
