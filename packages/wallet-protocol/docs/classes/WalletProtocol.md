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

[protocol/protocol.ts:20](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L20)

## Properties

### events

• **events**: `Record`<`string`, `Function`[]\>

#### Inherited from

EventEmitter.events

#### Defined in

[protocol/event-emitter.ts:3](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/wallet-protocol/src/ts/protocol/event-emitter.ts#L3)

___

### transport

• **transport**: `T`

#### Defined in

[protocol/protocol.ts:20](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L20)

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

[protocol/protocol.ts:36](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L36)

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

[protocol/protocol.ts:82](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L82)

___

### computeNx

▸ **computeNx**(): `Promise`<`Uint8Array`\>

#### Returns

`Promise`<`Uint8Array`\>

#### Defined in

[protocol/protocol.ts:28](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L28)

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

[protocol/protocol.ts:24](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L24)

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

[protocol/protocol.ts:164](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L164)

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

[protocol/protocol.ts:165](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L165)

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

[protocol/protocol.ts:166](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L166)

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

[protocol/protocol.ts:157](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L157)

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

[protocol/protocol.ts:158](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L158)

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

[protocol/protocol.ts:159](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L159)

___

### run

▸ **run**(): `Promise`<[`Session`](Session.md)<`T`\>\>

#### Returns

`Promise`<[`Session`](Session.md)<`T`\>\>

#### Defined in

[protocol/protocol.ts:116](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L116)

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

[protocol/protocol.ts:57](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2f254d6/packages/wallet-protocol/src/ts/protocol/protocol.ts#L57)
