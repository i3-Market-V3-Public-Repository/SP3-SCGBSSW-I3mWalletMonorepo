# Interface: NrpDltAgentDest

## Hierarchy

- `NrpDltAgent`

  ↳ **`NrpDltAgentDest`**

## Table of contents

### Properties

- [getSecretFromLedger](NrpDltAgentDest.md#getsecretfromledger)

### Methods

- [getContractAddress](NrpDltAgentDest.md#getcontractaddress)

## Properties

### getSecretFromLedger

• **getSecretFromLedger**: (`secretLength`: `number`, `signerAddress`: `string`, `exchangeId`: `string`, `timeout`: `number`) => `Promise`<{ `hex`: `string` ; `iat`: `number`  }\>

#### Type declaration

▸ (`secretLength`, `signerAddress`, `exchangeId`, `timeout`): `Promise`<{ `hex`: `string` ; `iat`: `number`  }\>

Just in case the PoP is not received, the secret can be downloaded from the ledger.
The secret should be downloaded before poo.iat + pooToPop max delay.

##### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `secretLength` | `number` | the expected length of the secret to get |
| `signerAddress` | `string` | the address (hexadecimal) of the entity publishing the secret. |
| `exchangeId` | `string` | the id of the data exchange |
| `timeout` | `number` | the timeout in seconds for waiting for the secret to be published on the ledger |

##### Returns

`Promise`<{ `hex`: `string` ; `iat`: `number`  }\>

the secret in hex and when it was published to the blockchain as a NumericDate

#### Defined in

[src/ts/dlt/agents/dest/NrpDltAgentDest.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/a844236/src/ts/dlt/agents/dest/NrpDltAgentDest.ts#L13)

## Methods

### getContractAddress

▸ `Abstract` **getContractAddress**(): `Promise`<`string`\>

Returns the address of the smart contract in use

#### Returns

`Promise`<`string`\>

#### Inherited from

NrpDltAgent.getContractAddress

#### Defined in

[src/ts/dlt/agents/NrpDltAgent.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/a844236/src/ts/dlt/agents/NrpDltAgent.ts#L9)
