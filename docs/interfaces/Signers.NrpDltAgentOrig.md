# Interface: NrpDltAgentOrig

[Signers](../modules/Signers.md).NrpDltAgentOrig

## Hierarchy

- `NrpDltAgent`

  ↳ **`NrpDltAgentOrig`**

## Implemented by

- [`EthersIoAgentOrig`](../classes/Signers.EthersIoAgentOrig.md)
- [`EthersIoAgentOrig`](../classes/EthersIoAgentOrig.md)
- [`I3mWalletAgentOrig`](../classes/Signers.I3mWalletAgentOrig.md)
- [`I3mWalletAgentOrig`](../classes/I3mWalletAgentOrig.md)

## Table of contents

### Methods

- [deploySecret](Signers.NrpDltAgentOrig.md#deploysecret)
- [getAddress](Signers.NrpDltAgentOrig.md#getaddress)
- [getContractAddress](Signers.NrpDltAgentOrig.md#getcontractaddress)

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

[src/ts/dlt/agents/orig/NrpDltAgentOrig.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/00bfe7f/src/ts/dlt/agents/orig/NrpDltAgentOrig.ts#L12)

___

### getAddress

▸ **getAddress**(): `Promise`<`string`\>

Returns and identifier of the signer's account on the ledger. In Ethereum-like DLTs is the Ethereum address

#### Returns

`Promise`<`string`\>

#### Defined in

[src/ts/dlt/agents/orig/NrpDltAgentOrig.ts:17](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/00bfe7f/src/ts/dlt/agents/orig/NrpDltAgentOrig.ts#L17)

___

### getContractAddress

▸ `Abstract` **getContractAddress**(): `Promise`<`string`\>

Returns the address of the smart contract in use

#### Returns

`Promise`<`string`\>

#### Inherited from

NrpDltAgent.getContractAddress

#### Defined in

[src/ts/dlt/agents/NrpDltAgent.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/00bfe7f/src/ts/dlt/agents/NrpDltAgent.ts#L9)
