# Class: LocalSessionManager<T\>

A session manager that uses the browser's Local Storage to store the wallet-protocol's session created after pairing with an i3M-Wallet app.

**`Deprecated`**

Use [SessionManager](SessionManager.md) instead. It will be removed in next major version update

## Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends `Transport` = `Transport` |

## Hierarchy

- [`SessionManager`](SessionManager.md)<`T`\>

  ↳ **`LocalSessionManager`**

## Table of contents

### Constructors

- [constructor](LocalSessionManager.md#constructor)

### Properties

- [$session](LocalSessionManager.md#$session)
- [fetch](LocalSessionManager.md#fetch)
- [initialized](LocalSessionManager.md#initialized)
- [protocol](LocalSessionManager.md#protocol)
- [session](LocalSessionManager.md#session)
- [storage](LocalSessionManager.md#storage)

### Accessors

- [hasSession](LocalSessionManager.md#hassession)

### Methods

- [createIfNotExists](LocalSessionManager.md#createifnotexists)
- [loadSession](LocalSessionManager.md#loadsession)
- [removeSession](LocalSessionManager.md#removesession)
- [setSession](LocalSessionManager.md#setsession)

## Constructors

### constructor

• **new LocalSessionManager**<`T`\>(`protocol`, `options?`)

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends `Transport`<`any`, `any`, `T`\> = `Transport`<`any`, `any`\> |

#### Parameters

| Name | Type |
| :------ | :------ |
| `protocol` | `WalletProtocol`<`T`\> |
| `options` | `Partial`<`SessionManagerOptions`\> |

#### Overrides

[SessionManager](SessionManager.md).[constructor](SessionManager.md#constructor)

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:105](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1ab480d/packages/wallet-protocol-utils/src/ts/session-manager.ts#L105)

## Properties

### $session

• **$session**: `Subject`<`undefined` \| `Session`<`T`\>\>

#### Inherited from

[SessionManager](SessionManager.md).[$session](SessionManager.md#$session)

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1ab480d/packages/wallet-protocol-utils/src/ts/session-manager.ts#L10)

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

#### Inherited from

[SessionManager](SessionManager.md).[fetch](SessionManager.md#fetch)

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:43](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1ab480d/packages/wallet-protocol-utils/src/ts/session-manager.ts#L43)

___

### initialized

• **initialized**: `Promise`<`boolean`\>

#### Inherited from

[SessionManager](SessionManager.md).[initialized](SessionManager.md#initialized)

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1ab480d/packages/wallet-protocol-utils/src/ts/session-manager.ts#L11)

___

### protocol

• `Protected` **protocol**: `WalletProtocol`<`T`\>

#### Inherited from

[SessionManager](SessionManager.md).[protocol](SessionManager.md#protocol)

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:105](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1ab480d/packages/wallet-protocol-utils/src/ts/session-manager.ts#L105)

___

### session

• **session**: `undefined` \| `Session`<`T`\>

#### Inherited from

[SessionManager](SessionManager.md).[session](SessionManager.md#session)

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1ab480d/packages/wallet-protocol-utils/src/ts/session-manager.ts#L9)

___

### storage

• `Protected` **storage**: `SessionStorage`

#### Inherited from

[SessionManager](SessionManager.md).[storage](SessionManager.md#storage)

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1ab480d/packages/wallet-protocol-utils/src/ts/session-manager.ts#L12)

## Accessors

### hasSession

• `get` **hasSession**(): `boolean`

#### Returns

`boolean`

#### Inherited from

SessionManager.hasSession

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:39](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1ab480d/packages/wallet-protocol-utils/src/ts/session-manager.ts#L39)

## Methods

### createIfNotExists

▸ **createIfNotExists**(): `Promise`<`Session`<`T`\>\>

#### Returns

`Promise`<`Session`<`T`\>\>

#### Inherited from

[SessionManager](SessionManager.md).[createIfNotExists](SessionManager.md#createifnotexists)

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:53](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1ab480d/packages/wallet-protocol-utils/src/ts/session-manager.ts#L53)

___

### loadSession

▸ **loadSession**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Inherited from

[SessionManager](SessionManager.md).[loadSession](SessionManager.md#loadsession)

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:84](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1ab480d/packages/wallet-protocol-utils/src/ts/session-manager.ts#L84)

___

### removeSession

▸ **removeSession**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Inherited from

[SessionManager](SessionManager.md).[removeSession](SessionManager.md#removesession)

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:65](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1ab480d/packages/wallet-protocol-utils/src/ts/session-manager.ts#L65)

___

### setSession

▸ **setSession**(`session?`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `session?` | `Session`<`T`\> |

#### Returns

`Promise`<`void`\>

#### Inherited from

[SessionManager](SessionManager.md).[setSession](SessionManager.md#setsession)

#### Defined in

[wallet-protocol-utils/src/ts/session-manager.ts:71](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1ab480d/packages/wallet-protocol-utils/src/ts/session-manager.ts#L71)
