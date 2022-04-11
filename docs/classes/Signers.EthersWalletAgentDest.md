# Class: EthersWalletAgentDest

[Signers](../modules/Signers.md).EthersWalletAgentDest

A ledger signer using an ethers.io Wallet.

## Hierarchy

- `EthersWalletAgent`

  ↳ **`EthersWalletAgentDest`**

  ↳↳ [`I3mWalletAgentDest`](Signers.I3mWalletAgentDest.md)

  ↳↳ [`I3mWalletAgentDest`](I3mWalletAgentDest.md)

## Implements

- [`WalletAgentDest`](../interfaces/Signers.WalletAgentDest.md)

## Table of contents

### Constructors

- [constructor](Signers.EthersWalletAgentDest.md#constructor)

### Properties

- [contract](Signers.EthersWalletAgentDest.md#contract)
- [dltConfig](Signers.EthersWalletAgentDest.md#dltconfig)
- [provider](Signers.EthersWalletAgentDest.md#provider)

### Methods

- [getContractAddress](Signers.EthersWalletAgentDest.md#getcontractaddress)
- [getSecretFromLedger](Signers.EthersWalletAgentDest.md#getsecretfromledger)

## Constructors

### constructor

• **new EthersWalletAgentDest**(`dltConfig?`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `dltConfig?` | `Partial`<[`DltConfig`](../interfaces/DltConfig.md)\> |

#### Inherited from

EthersWalletAgent.constructor

#### Defined in

[src/ts/dlt/wallet-agents/EthersWalletAgent.ts:14](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/b64ca83/src/ts/dlt/wallet-agents/EthersWalletAgent.ts#L14)

## Properties

### contract

• **contract**: `Contract`

#### Inherited from

EthersWalletAgent.contract

#### Defined in

[src/ts/dlt/wallet-agents/EthersWalletAgent.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/b64ca83/src/ts/dlt/wallet-agents/EthersWalletAgent.ts#L11)

___

### dltConfig

• **dltConfig**: [`DltConfig`](../interfaces/DltConfig.md)

#### Inherited from

EthersWalletAgent.dltConfig

#### Defined in

[src/ts/dlt/wallet-agents/EthersWalletAgent.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/b64ca83/src/ts/dlt/wallet-agents/EthersWalletAgent.ts#L10)

___

### provider

• **provider**: `Provider`

#### Inherited from

EthersWalletAgent.provider

#### Defined in

[src/ts/dlt/wallet-agents/EthersWalletAgent.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/b64ca83/src/ts/dlt/wallet-agents/EthersWalletAgent.ts#L12)

## Methods

### getContractAddress

▸ **getContractAddress**(): `Promise`<`string`\>

Returns the address of the smart contract in use

#### Returns

`Promise`<`string`\>

#### Implementation of

[WalletAgentDest](../interfaces/Signers.WalletAgentDest.md).[getContractAddress](../interfaces/Signers.WalletAgentDest.md#getcontractaddress)

#### Inherited from

EthersWalletAgent.getContractAddress

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

#### Implementation of

[WalletAgentDest](../interfaces/Signers.WalletAgentDest.md).[getSecretFromLedger](../interfaces/Signers.WalletAgentDest.md#getsecretfromledger)

#### Defined in

[src/ts/dlt/wallet-agents/dest/EthersWalletAgentDest.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/b64ca83/src/ts/dlt/wallet-agents/dest/EthersWalletAgentDest.ts#L13)
