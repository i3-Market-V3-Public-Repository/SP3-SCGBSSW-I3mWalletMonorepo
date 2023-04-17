# Class: Session<T\>

## Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends [`Transport`](../interfaces/Transport.md) |

## Table of contents

### Constructors

- [constructor](Session.md#constructor)

### Properties

- [code](Session.md#code)
- [masterKey](Session.md#masterkey)
- [transport](Session.md#transport)

### Methods

- [send](Session.md#send)
- [toJSON](Session.md#tojson)
- [fromJSON](Session.md#fromjson)

## Constructors

### constructor

• **new Session**<`T`\>(`transport`, `masterKey`, `code`)

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends [`Transport`](../interfaces/Transport.md)<`any`, `any`, `T`\> |

#### Parameters

| Name | Type |
| :------ | :------ |
| `transport` | `T` |
| `masterKey` | [`MasterKey`](MasterKey.md) |
| `code` | `Uint8Array` |

#### Defined in

[src/ts/protocol/session.ts:5](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/13bce7cb/packages/wallet-protocol/src/ts/protocol/session.ts#L5)

## Properties

### code

• `Protected` **code**: `Uint8Array`

#### Defined in

[src/ts/protocol/session.ts:5](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/13bce7cb/packages/wallet-protocol/src/ts/protocol/session.ts#L5)

___

### masterKey

• `Protected` **masterKey**: [`MasterKey`](MasterKey.md)

#### Defined in

[src/ts/protocol/session.ts:5](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/13bce7cb/packages/wallet-protocol/src/ts/protocol/session.ts#L5)

___

### transport

• `Protected` **transport**: `T`

#### Defined in

[src/ts/protocol/session.ts:5](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/13bce7cb/packages/wallet-protocol/src/ts/protocol/session.ts#L5)

## Methods

### send

▸ **send**(`request`): `Promise`<[`TransportResponse`](../API.md#transportresponse)<`T`\>\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `request` | [`TransportRequest`](../API.md#transportrequest)<`T`\> |

#### Returns

`Promise`<[`TransportResponse`](../API.md#transportresponse)<`T`\>\>

#### Defined in

[src/ts/protocol/session.ts:7](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/13bce7cb/packages/wallet-protocol/src/ts/protocol/session.ts#L7)

___

### toJSON

▸ **toJSON**(): `any`

#### Returns

`any`

#### Defined in

[src/ts/protocol/session.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/13bce7cb/packages/wallet-protocol/src/ts/protocol/session.ts#L11)

___

### fromJSON

▸ `Static` **fromJSON**<`T`\>(`transport`, `json`): `Promise`<[`Session`](Session.md)<`T`\>\>

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends [`Transport`](../interfaces/Transport.md)<`any`, `any`, `T`\> |

#### Parameters

| Name | Type |
| :------ | :------ |
| `transport` | `T` |
| `json` | `any` |

#### Returns

`Promise`<[`Session`](Session.md)<`T`\>\>

#### Defined in

[src/ts/protocol/session.ts:18](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/13bce7cb/packages/wallet-protocol/src/ts/protocol/session.ts#L18)

▸ `Static` **fromJSON**<`T`\>(`transportConstructor`, `json`): `Promise`<[`Session`](Session.md)<`T`\>\>

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends [`Transport`](../interfaces/Transport.md)<`any`, `any`, `T`\> |

#### Parameters

| Name | Type |
| :------ | :------ |
| `transportConstructor` | () => `T` |
| `json` | `any` |

#### Returns

`Promise`<[`Session`](Session.md)<`T`\>\>

#### Defined in

[src/ts/protocol/session.ts:19](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/13bce7cb/packages/wallet-protocol/src/ts/protocol/session.ts#L19)
