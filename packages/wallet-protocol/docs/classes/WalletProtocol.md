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

- [events](WalletProtocol.md#events)
- [transport](WalletProtocol.md#transport)

### Methods

- [computeCx](WalletProtocol.md#computecx)
- [computeMasterKey](WalletProtocol.md#computemasterkey)
- [computeNx](WalletProtocol.md#computenx)
- [computeR](WalletProtocol.md#computer)
- [emit](WalletProtocol.md#emit)
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

[src/ts/protocol/protocol.ts:21](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b8285f6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L21)

## Properties

### events

• **events**: `Record`<`string`, `Function`[]\>

#### Inherited from

EventEmitter.events

#### Defined in

[src/ts/protocol/event-emitter.ts:3](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b8285f6/packages/wallet-protocol/src/ts/protocol/event-emitter.ts#L3)

___

### transport

• **transport**: `T`

#### Defined in

[src/ts/protocol/protocol.ts:21](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b8285f6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L21)

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

[src/ts/protocol/protocol.ts:37](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b8285f6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L37)

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

[src/ts/protocol/protocol.ts:83](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b8285f6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L83)

___

### computeNx

▸ **computeNx**(): `Promise`<`Uint8Array`\>

#### Returns

`Promise`<`Uint8Array`\>

#### Defined in

[src/ts/protocol/protocol.ts:29](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b8285f6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L29)

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

[src/ts/protocol/protocol.ts:25](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b8285f6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L25)

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

[src/ts/protocol/protocol.ts:173](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b8285f6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L173)

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

[src/ts/protocol/protocol.ts:174](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b8285f6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L174)

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

[src/ts/protocol/protocol.ts:175](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b8285f6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L175)

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

[src/ts/protocol/protocol.ts:166](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b8285f6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L166)

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

[src/ts/protocol/protocol.ts:167](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b8285f6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L167)

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

[src/ts/protocol/protocol.ts:168](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b8285f6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L168)

___

### run

▸ **run**(): `Promise`<[`Session`](Session.md)<`T`\>\>

#### Returns

`Promise`<[`Session`](Session.md)<`T`\>\>

#### Defined in

[src/ts/protocol/protocol.ts:117](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b8285f6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L117)

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

[src/ts/protocol/protocol.ts:58](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/b8285f6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L58)
