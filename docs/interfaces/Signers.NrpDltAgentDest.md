# Interface: NrpDltAgentDest

[Signers](../modules/Signers.md).NrpDltAgentDest

## Hierarchy

- `NrpDltAgent`

  ↳ **`NrpDltAgentDest`**

## Implemented by

- [`EthersIoAgentDest`](../classes/Signers.EthersIoAgentDest.md)
- [`EthersIoAgentDest`](../classes/EthersIoAgentDest.md)
- [`I3mServerWalletAgentDest`](../classes/Signers.I3mServerWalletAgentDest.md)
- [`I3mServerWalletAgentDest`](../classes/I3mServerWalletAgentDest.md)
- [`I3mWalletAgentDest`](../classes/Signers.I3mWalletAgentDest.md)
- [`I3mWalletAgentDest`](../classes/I3mWalletAgentDest.md)

## Table of contents

### Properties

- [getSecretFromLedger](Signers.NrpDltAgentDest.md#getsecretfromledger)

### Methods

- [getContractAddress](Signers.NrpDltAgentDest.md#getcontractaddress)

## Properties

### getSecretFromLedger

• **getSecretFromLedger**: (`signerAddress`: `string`, `exchangeId`: `string`, `timeout`: `number`) => `Promise`<{ `hex`: `string` ; `iat`: `number`  }\>

#### Type declaration

▸ (`signerAddress`, `exchangeId`, `timeout`): `Promise`<{ `hex`: `string` ; `iat`: `number`  }\>

Just in case the PoP is not received, the secret can be downloaded from the ledger.
The secret should be downloaded before poo.iat + pooToPop max delay.

##### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `signerAddress` | `string` | the address (hexadecimal) of the entity publishing the secret. |
| `exchangeId` | `string` | the id of the data exchange |
| `timeout` | `number` | the timeout in seconds for waiting for the secret to be published on the ledger |

##### Returns

`Promise`<{ `hex`: `string` ; `iat`: `number`  }\>

the secret in hex and when it was published to the blockchain as a NumericDate

#### Defined in

[src/ts/dlt/agents/dest/NrpDltAgentDest.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/04fcfd0/src/ts/dlt/agents/dest/NrpDltAgentDest.ts#L12)

## Methods

### getContractAddress

▸ `Abstract` **getContractAddress**(): `Promise`<`string`\>

Returns the address of the smart contract in use

#### Returns

`Promise`<`string`\>

#### Inherited from

NrpDltAgent.getContractAddress

#### Defined in

[src/ts/dlt/agents/NrpDltAgent.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/04fcfd0/src/ts/dlt/agents/NrpDltAgent.ts#L9)