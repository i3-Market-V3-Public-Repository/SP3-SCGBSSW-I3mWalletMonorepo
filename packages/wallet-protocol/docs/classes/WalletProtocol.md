# Class: WalletProtocol<T\>

## Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends [`Transport`](../interfaces/Transport.md) = [`Transport`](../interfaces/Transport.md) |

## Hierarchy

- `EventEmitter`

  ↳ **`WalletProtocol`**

## Table of contents

### Constructors

- [constructor](WalletProtocol.md#constructor)

### Properties

- [\_running](WalletProtocol.md#_running)
- [events](WalletProtocol.md#events)
- [transport](WalletProtocol.md#transport)

### Accessors

- [isRunning](WalletProtocol.md#isrunning)

### Methods

- [computeCx](WalletProtocol.md#computecx)
- [computeMasterKey](WalletProtocol.md#computemasterkey)
- [computeNx](WalletProtocol.md#computenx)
- [computeR](WalletProtocol.md#computer)
- [emit](WalletProtocol.md#emit)
- [finish](WalletProtocol.md#finish)
- [on](WalletProtocol.md#on)
- [run](WalletProtocol.md#run)
- [validateAuthData](WalletProtocol.md#validateauthdata)

## Constructors

### constructor

• **new WalletProtocol**<`T`\>(`transport`)

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends [`Transport`](../interfaces/Transport.md)<`any`, `any`, `T`\> = [`Transport`](../interfaces/Transport.md)<`any`, `any`\> |

#### Parameters

| Name | Type |
| :------ | :------ |
| `transport` | `T` |

#### Overrides

EventEmitter.constructor

#### Defined in

[src/ts/protocol/protocol.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/protocol/protocol.ts#L22)

## Properties

### \_running

• **\_running**: `undefined` \| `Promise`<[`Session`](Session.md)<`T`\>\>

#### Defined in

[src/ts/protocol/protocol.ts:21](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/protocol/protocol.ts#L21)

___

### events

• **events**: `Record`<`string`, `Function`[]\>

#### Inherited from

EventEmitter.events

#### Defined in

[src/ts/protocol/event-emitter.ts:3](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/protocol/event-emitter.ts#L3)

___

### transport

• **transport**: `T`

#### Defined in

[src/ts/protocol/protocol.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/protocol/protocol.ts#L22)

## Accessors

### isRunning

• `get` **isRunning**(): `boolean`

#### Returns

`boolean`

#### Defined in

[src/ts/protocol/protocol.ts:173](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/protocol/protocol.ts#L173)

## Methods

### computeCx

▸ **computeCx**(`pkeData`, `nx`, `r`): `Promise`<`Uint8Array`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `pkeData` | [`ProtocolPKEData`](../interfaces/ProtocolPKEData.md) |
| `nx` | `Uint8Array` |
| `r` | `Uint8Array` |

#### Returns

`Promise`<`Uint8Array`\>

#### Defined in

[src/ts/protocol/protocol.ts:38](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/protocol/protocol.ts#L38)

___

### computeMasterKey

▸ **computeMasterKey**(`ecdh`, `fullPkeData`, `fullAuthData`): `Promise`<[`MasterKey`](MasterKey.md)\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `ecdh` | `BaseECDH` |
| `fullPkeData` | [`ProtocolPKEData`](../interfaces/ProtocolPKEData.md) |
| `fullAuthData` | [`ProtocolAuthData`](../interfaces/ProtocolAuthData.md) |

#### Returns

`Promise`<[`MasterKey`](MasterKey.md)\>

#### Defined in

[src/ts/protocol/protocol.ts:84](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/protocol/protocol.ts#L84)

___

### computeNx

▸ **computeNx**(): `Promise`<`Uint8Array`\>

#### Returns

`Promise`<`Uint8Array`\>

#### Defined in

[src/ts/protocol/protocol.ts:30](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/protocol/protocol.ts#L30)

___

### computeR

▸ **computeR**(`ra`, `rb`): `Promise`<`Uint8Array`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `ra` | `Uint8Array` |
| `rb` | `Uint8Array` |

#### Returns

`Promise`<`Uint8Array`\>

#### Defined in

[src/ts/protocol/protocol.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/protocol/protocol.ts#L26)

___

### emit

▸ **emit**(`event`, `connString`): `boolean`

#### Parameters

| Name | Type |
| :------ | :------ |
| `event` | ``"connString"`` |
| `connString` | [`ConnectionString`](ConnectionString.md) |

#### Returns

`boolean`

#### Overrides

EventEmitter.emit

#### Defined in

[src/ts/protocol/protocol.ts:191](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/protocol/protocol.ts#L191)

▸ **emit**(`event`, `masterKey`): `boolean`

#### Parameters

| Name | Type |
| :------ | :------ |
| `event` | ``"masterKey"`` |
| `masterKey` | [`MasterKey`](MasterKey.md) |

#### Returns

`boolean`

#### Overrides

EventEmitter.emit

#### Defined in

[src/ts/protocol/protocol.ts:192](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/protocol/protocol.ts#L192)

▸ **emit**(`event`): `boolean`

#### Parameters

| Name | Type |
| :------ | :------ |
| `event` | ``"finished"`` |

#### Returns

`boolean`

#### Overrides

EventEmitter.emit

#### Defined in

[src/ts/protocol/protocol.ts:193](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/protocol/protocol.ts#L193)

___

### finish

▸ **finish**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

[src/ts/protocol/protocol.ts:177](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/protocol/protocol.ts#L177)

___

### on

▸ **on**(`event`, `listener`): [`WalletProtocol`](WalletProtocol.md)<`T`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `event` | ``"connString"`` |
| `listener` | (`connString`: [`ConnectionString`](ConnectionString.md)) => `void` |

#### Returns

[`WalletProtocol`](WalletProtocol.md)<`T`\>

#### Overrides

EventEmitter.on

#### Defined in

[src/ts/protocol/protocol.ts:184](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/protocol/protocol.ts#L184)

▸ **on**(`event`, `listener`): [`WalletProtocol`](WalletProtocol.md)<`T`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `event` | ``"masterKey"`` |
| `listener` | (`masterKey`: [`MasterKey`](MasterKey.md)) => `void` |

#### Returns

[`WalletProtocol`](WalletProtocol.md)<`T`\>

#### Overrides

EventEmitter.on

#### Defined in

[src/ts/protocol/protocol.ts:185](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/protocol/protocol.ts#L185)

▸ **on**(`event`, `listener`): [`WalletProtocol`](WalletProtocol.md)<`T`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `event` | ``"finished"`` |
| `listener` | () => `void` |

#### Returns

[`WalletProtocol`](WalletProtocol.md)<`T`\>

#### Overrides

EventEmitter.on

#### Defined in

[src/ts/protocol/protocol.ts:186](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/protocol/protocol.ts#L186)

___

### run

▸ **run**(): `Promise`<[`Session`](Session.md)<`T`\>\>

#### Returns

`Promise`<[`Session`](Session.md)<`T`\>\>

#### Defined in

[src/ts/protocol/protocol.ts:118](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/protocol/protocol.ts#L118)

___

### validateAuthData

▸ **validateAuthData**(`fullPkeData`, `fullAuthData`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `fullPkeData` | [`ProtocolPKEData`](../interfaces/ProtocolPKEData.md) |
| `fullAuthData` | [`ProtocolAuthData`](../interfaces/ProtocolAuthData.md) |

#### Returns

`Promise`<`void`\>

#### Defined in

[src/ts/protocol/protocol.ts:59](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/protocol/protocol.ts#L59)
