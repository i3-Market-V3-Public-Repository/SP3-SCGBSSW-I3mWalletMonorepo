# Class: SessionManager<T\>

A session manager is used to create, remove, set and load wallet-protocol sessions created after sucessful pairing with a i3M-Wallet app.

## Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends `Transport` = `Transport` |

## Hierarchy

- **`SessionManager`**

  ↳ [`LocalSessionManager`](LocalSessionManager.md)

## Table of contents

### Constructors

- [constructor](SessionManager.md#constructor)

### Properties

- [$session](SessionManager.md#$session)
- [fetch](SessionManager.md#fetch)
- [initialized](SessionManager.md#initialized)
- [protocol](SessionManager.md#protocol)
- [session](SessionManager.md#session)
- [storage](SessionManager.md#storage)

### Accessors

- [hasSession](SessionManager.md#hassession)

### Methods

- [createIfNotExists](SessionManager.md#createifnotexists)
- [loadSession](SessionManager.md#loadsession)
- [removeSession](SessionManager.md#removesession)
- [setSession](SessionManager.md#setsession)

## Constructors

### constructor

• **new SessionManager**<`T`\>(`options`)

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends `Transport`<`any`, `any`, `T`\> = `Transport`<`any`, `any`\> |

#### Parameters

| Name | Type |
| :------ | :------ |
| `options` | [`SessionManagerOpts`](../interfaces/SessionManagerOpts.md)<`T`\> |

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:15](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/wallet-protocol-utils/src/ts/session-manager.ts#L15)

## Properties

### $session

• **$session**: `Subject`<`undefined` \| `Session`<`T`\>\>

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/wallet-protocol-utils/src/ts/session-manager.ts#L10)

___

### fetch

• **fetch**: (`request`: `TransportRequest`<`T`\>) => `Promise`<`TransportResponse`<`T`\>\>

#### Type declaration

▸ (`request`): `Promise`<`TransportResponse`<`T`\>\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `request` | `TransportRequest`<`T`\> |

##### Returns

`Promise`<`TransportResponse`<`T`\>\>

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:39](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/wallet-protocol-utils/src/ts/session-manager.ts#L39)

___

### initialized

• **initialized**: `Promise`<`void`\>

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/wallet-protocol-utils/src/ts/session-manager.ts#L11)

___

### protocol

• `Protected` **protocol**: `WalletProtocol`<`T`\>

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/wallet-protocol-utils/src/ts/session-manager.ts#L13)

___

### session

• **session**: `undefined` \| `Session`<`T`\>

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/wallet-protocol-utils/src/ts/session-manager.ts#L9)

___

### storage

• `Protected` **storage**: [`SessionStorage`](../interfaces/SessionStorage.md)

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/wallet-protocol-utils/src/ts/session-manager.ts#L12)

## Accessors

### hasSession

• `get` **hasSession**(): `boolean`

#### Returns

`boolean`

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:35](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/wallet-protocol-utils/src/ts/session-manager.ts#L35)

## Methods

### createIfNotExists

▸ **createIfNotExists**(): `Promise`<`Session`<`T`\>\>

#### Returns

`Promise`<`Session`<`T`\>\>

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:49](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/wallet-protocol-utils/src/ts/session-manager.ts#L49)

___

### loadSession

▸ **loadSession**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:80](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/wallet-protocol-utils/src/ts/session-manager.ts#L80)

___

### removeSession

▸ **removeSession**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:61](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/wallet-protocol-utils/src/ts/session-manager.ts#L61)

___

### setSession

▸ **setSession**(`session?`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `session?` | `Session`<`T`\> |

#### Returns

`Promise`<`void`\>

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:67](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/wallet-protocol-utils/src/ts/session-manager.ts#L67)
