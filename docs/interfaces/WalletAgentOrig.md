# Interface: WalletAgentOrig

## Hierarchy

- `WalletAgent`

  ↳ **`WalletAgentOrig`**

## Table of contents

### Methods

- [deploySecret](WalletAgentOrig.md#deploysecret)
- [getAddress](WalletAgentOrig.md#getaddress)
- [getContractAddress](WalletAgentOrig.md#getcontractaddress)

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

#### Defined in

src/ts/dlt/wallet-agents/orig/WalletAgentOrig.ts:12

___

### getAddress

▸ **getAddress**(): `Promise`<`string`\>

Returns and identifier of the signer's account on the ledger. In Ethereum-like DLTs is the Ethereum address

#### Returns

`Promise`<`string`\>

#### Defined in

src/ts/dlt/wallet-agents/orig/WalletAgentOrig.ts:17

___

### getContractAddress

▸ `Abstract` **getContractAddress**(): `Promise`<`string`\>

Returns the address of the smart contract in use

#### Returns

`Promise`<`string`\>

#### Inherited from

WalletAgent.getContractAddress

#### Defined in

src/ts/dlt/wallet-agents/WalletAgent.ts:10
