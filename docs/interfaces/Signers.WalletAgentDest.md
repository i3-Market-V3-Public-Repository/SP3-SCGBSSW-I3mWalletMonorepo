# Interface: WalletAgentDest

[Signers](../modules/Signers.md).WalletAgentDest

## Hierarchy

- `WalletAgent`

  ↳ **`WalletAgentDest`**

## Implemented by

- [`EthersWalletAgentDest`](../classes/Signers.EthersWalletAgentDest.md)
- [`EthersWalletAgentDest`](../classes/EthersWalletAgentDest.md)

## Table of contents

### Methods

- [getContractAddress](Signers.WalletAgentDest.md#getcontractaddress)
- [getSecretFromLedger](Signers.WalletAgentDest.md#getsecretfromledger)

## Methods

### getContractAddress

▸ `Abstract` **getContractAddress**(): `Promise`<`string`\>

Returns the address of the smart contract in use

#### Returns

`Promise`<`string`\>

#### Inherited from

WalletAgent.getContractAddress

#### Defined in

[src/ts/dlt/wallet-agents/WalletAgent.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/6ca578f/src/ts/dlt/wallet-agents/WalletAgent.ts#L10)

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

#### Defined in

[src/ts/dlt/wallet-agents/dest/WalletAgentDest.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/6ca578f/src/ts/dlt/wallet-agents/dest/WalletAgentDest.ts#L12)
