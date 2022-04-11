# Interface: WalletAgentOrig

[Signers](../modules/Signers.md).WalletAgentOrig

## Hierarchy

- `WalletAgent`

  ↳ **`WalletAgentOrig`**

## Implemented by

- [`EthersWalletAgentOrig`](../classes/Signers.EthersWalletAgentOrig.md)
- [`EthersWalletAgentOrig`](../classes/EthersWalletAgentOrig.md)
- [`I3mWalletAgentOrig`](../classes/Signers.I3mWalletAgentOrig.md)
- [`I3mWalletAgentOrig`](../classes/I3mWalletAgentOrig.md)

## Table of contents

### Methods

- [deploySecret](Signers.WalletAgentOrig.md#deploysecret)
- [getAddress](Signers.WalletAgentOrig.md#getaddress)
- [getContractAddress](Signers.WalletAgentOrig.md#getcontractaddress)

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

#### Defined in

[src/ts/dlt/wallet-agents/orig/WalletAgentOrig.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/b64ca83/src/ts/dlt/wallet-agents/orig/WalletAgentOrig.ts#L12)

___

### getAddress

▸ **getAddress**(): `Promise`<`string`\>

Returns and identifier of the signer's account on the ledger. In Ethereum-like DLTs is the Ethereum address

#### Returns

`Promise`<`string`\>

#### Defined in

[src/ts/dlt/wallet-agents/orig/WalletAgentOrig.ts:17](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/b64ca83/src/ts/dlt/wallet-agents/orig/WalletAgentOrig.ts#L17)

___

### getContractAddress

▸ `Abstract` **getContractAddress**(): `Promise`<`string`\>

Returns the address of the smart contract in use

#### Returns

`Promise`<`string`\>

#### Inherited from

WalletAgent.getContractAddress

#### Defined in

[src/ts/dlt/wallet-agents/WalletAgent.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/b64ca83/src/ts/dlt/wallet-agents/WalletAgent.ts#L10)
