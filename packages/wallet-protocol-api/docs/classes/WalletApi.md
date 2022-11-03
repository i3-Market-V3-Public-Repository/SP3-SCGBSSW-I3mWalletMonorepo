# Class: WalletApi

## Implements

- `ApiExecutor`

## Table of contents

### Constructors

- [constructor](WalletApi.md#constructor)

### Properties

- [didJwt](WalletApi.md#didjwt)
- [disclosure](WalletApi.md#disclosure)
- [identities](WalletApi.md#identities)
- [providerinfo](WalletApi.md#providerinfo)
- [resources](WalletApi.md#resources)
- [session](WalletApi.md#session)
- [transaction](WalletApi.md#transaction)

### Methods

- [executeQuery](WalletApi.md#executequery)

## Constructors

### constructor

• **new WalletApi**(`session`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `session` | `Session`<`HttpInitiatorTransport`\> |

#### Defined in

[api.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/01a8348/packages/wallet-protocol-api/src/ts/api.ts#L13)

## Properties

### didJwt

• **didJwt**: `DidJwtApi`

#### Defined in

[api.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/01a8348/packages/wallet-protocol-api/src/ts/api.ts#L10)

___

### disclosure

• **disclosure**: `DisclosureApi`

#### Defined in

[api.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/01a8348/packages/wallet-protocol-api/src/ts/api.ts#L9)

___

### identities

• **identities**: `IdentitiesApi`

#### Defined in

[api.ts:6](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/01a8348/packages/wallet-protocol-api/src/ts/api.ts#L6)

___

### providerinfo

• **providerinfo**: `ProviderInfoApi`

#### Defined in

[api.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/01a8348/packages/wallet-protocol-api/src/ts/api.ts#L11)

___

### resources

• **resources**: `ResourcesApi`

#### Defined in

[api.ts:8](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/01a8348/packages/wallet-protocol-api/src/ts/api.ts#L8)

___

### session

• `Protected` **session**: `Session`<`HttpInitiatorTransport`\>

#### Defined in

[api.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/01a8348/packages/wallet-protocol-api/src/ts/api.ts#L13)

___

### transaction

• **transaction**: `TransactionApi`

#### Defined in

[api.ts:7](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/01a8348/packages/wallet-protocol-api/src/ts/api.ts#L7)

## Methods

### executeQuery

▸ **executeQuery**<`T`\>(`api`, `pathParams`, `queryParams`, `bodyObject`): `Promise`<`T`\>

#### Type parameters

| Name |
| :------ |
| `T` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `api` | `ApiMethod` |
| `pathParams` | `Params` |
| `queryParams` | `Params` |
| `bodyObject` | `any` |

#### Returns

`Promise`<`T`\>

#### Implementation of

ApiExecutor.executeQuery

#### Defined in

[api.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/01a8348/packages/wallet-protocol-api/src/ts/api.ts#L22)
