# Class: I3mWalletAgentDest

[Signers](../modules/Signers.md).I3mWalletAgentDest

## Hierarchy

- [`EthersWalletAgentDest`](Signers.EthersWalletAgentDest.md)

  ↳ **`I3mWalletAgentDest`**

## Table of contents

### Constructors

- [constructor](Signers.I3mWalletAgentDest.md#constructor)

### Properties

- [contract](Signers.I3mWalletAgentDest.md#contract)
- [dltConfig](Signers.I3mWalletAgentDest.md#dltconfig)
- [provider](Signers.I3mWalletAgentDest.md#provider)

### Methods

- [getContractAddress](Signers.I3mWalletAgentDest.md#getcontractaddress)
- [getSecretFromLedger](Signers.I3mWalletAgentDest.md#getsecretfromledger)

## Constructors

### constructor

• **new I3mWalletAgentDest**(`dltConfig?`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `dltConfig?` | `Partial`<[`DltConfig`](../interfaces/DltConfig.md)\> |

#### Inherited from

[EthersWalletAgentDest](Signers.EthersWalletAgentDest.md).[constructor](Signers.EthersWalletAgentDest.md#constructor)

#### Defined in

[src/ts/dlt/wallet-agents/EthersWalletAgent.ts:14](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/b64ca83/src/ts/dlt/wallet-agents/EthersWalletAgent.ts#L14)

## Properties

### contract

• **contract**: `Contract`

#### Inherited from

[EthersWalletAgentDest](Signers.EthersWalletAgentDest.md).[contract](Signers.EthersWalletAgentDest.md#contract)

#### Defined in

[src/ts/dlt/wallet-agents/EthersWalletAgent.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/b64ca83/src/ts/dlt/wallet-agents/EthersWalletAgent.ts#L11)

___

### dltConfig

• **dltConfig**: [`DltConfig`](../interfaces/DltConfig.md)

#### Inherited from

[EthersWalletAgentDest](Signers.EthersWalletAgentDest.md).[dltConfig](Signers.EthersWalletAgentDest.md#dltconfig)

#### Defined in

[src/ts/dlt/wallet-agents/EthersWalletAgent.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/b64ca83/src/ts/dlt/wallet-agents/EthersWalletAgent.ts#L10)

___

### provider

• **provider**: `Provider`

#### Inherited from

[EthersWalletAgentDest](Signers.EthersWalletAgentDest.md).[provider](Signers.EthersWalletAgentDest.md#provider)

#### Defined in

[src/ts/dlt/wallet-agents/EthersWalletAgent.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/b64ca83/src/ts/dlt/wallet-agents/EthersWalletAgent.ts#L12)

## Methods

### getContractAddress

▸ **getContractAddress**(): `Promise`<`string`\>

Returns the address of the smart contract in use

#### Returns

`Promise`<`string`\>

#### Inherited from

[EthersWalletAgentDest](Signers.EthersWalletAgentDest.md).[getContractAddress](Signers.EthersWalletAgentDest.md#getcontractaddress)

#### Defined in

[src/ts/dlt/wallet-agents/EthersWalletAgent.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/b64ca83/src/ts/dlt/wallet-agents/EthersWalletAgent.ts#L26)

___

### getSecretFromLedger

▸ **getSecretFromLedger**(`signerAddress`, `exchangeId`, `timeout`): `Promise`<{ `hex`: `string` ; `iat`: `number`  }\>

Just in case the PoP is not received, the secret can be downloaded from the ledger.
The secret should be downloaded before poo.iat + pooToPop max delay.

#### Parameters

| Name | Type |
| :------ | :------ |
| `signerAddress` | `string` |
| `exchangeId` | `string` |
| `timeout` | `number` |

#### Returns

`Promise`<{ `hex`: `string` ; `iat`: `number`  }\>

#### Inherited from

[EthersWalletAgentDest](Signers.EthersWalletAgentDest.md).[getSecretFromLedger](Signers.EthersWalletAgentDest.md#getsecretfromledger)

#### Defined in

[src/ts/dlt/wallet-agents/dest/EthersWalletAgentDest.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/b64ca83/src/ts/dlt/wallet-agents/dest/EthersWalletAgentDest.ts#L13)
