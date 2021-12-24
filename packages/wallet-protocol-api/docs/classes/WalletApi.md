# Class: WalletApi

## Table of contents

### Constructors

- [constructor](WalletApi.md#constructor)

### Properties

- [session](WalletApi.md#session)

### Methods

- [getIdentites](WalletApi.md#getidentites)

## Constructors

### constructor

• **new WalletApi**(`session`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `session` | `Session`<`HttpInitiatorTransport`\> |

#### Defined in

[api.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/59e03a5/packages/wallet-protocol-api/src/ts/api.ts#L9)

## Properties

### session

• `Protected` **session**: `Session`<`HttpInitiatorTransport`\>

## Methods

### getIdentites

▸ **getIdentites**(`queryParams?`): `Promise`<`IdentityListInput`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `queryParams?` | `QueryParameters` |

#### Returns

`Promise`<`IdentityListInput`\>

#### Defined in

[api.ts:37](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/59e03a5/packages/wallet-protocol-api/src/ts/api.ts#L37)
