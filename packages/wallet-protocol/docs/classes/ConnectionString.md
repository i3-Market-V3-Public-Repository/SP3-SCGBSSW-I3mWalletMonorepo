# Class: ConnectionString

## Table of contents

### Constructors

- [constructor](ConnectionString.md#constructor)

### Properties

- [buffer](ConnectionString.md#buffer)
- [l](ConnectionString.md#l)

### Methods

- [extractPort](ConnectionString.md#extractport)
- [extractRb](ConnectionString.md#extractrb)
- [toString](ConnectionString.md#tostring)
- [fromString](ConnectionString.md#fromstring)
- [generate](ConnectionString.md#generate)

## Constructors

### constructor

• **new ConnectionString**(`buffer`, `l`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `buffer` | `Uint8Array` |
| `l` | `number` |

#### Defined in

[protocol/connection-string.ts:4](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/0457b78/packages/wallet-protocol/src/ts/protocol/connection-string.ts#L4)

## Properties

### buffer

• `Protected` **buffer**: `Uint8Array`

#### Defined in

[protocol/connection-string.ts:4](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/0457b78/packages/wallet-protocol/src/ts/protocol/connection-string.ts#L4)

___

### l

• `Protected` **l**: `number`

#### Defined in

[protocol/connection-string.ts:4](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/0457b78/packages/wallet-protocol/src/ts/protocol/connection-string.ts#L4)

## Methods

### extractPort

▸ **extractPort**(): `number`

#### Returns

`number`

#### Defined in

[protocol/connection-string.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/0457b78/packages/wallet-protocol/src/ts/protocol/connection-string.ts#L10)

___

### extractRb

▸ **extractRb**(): `Uint8Array`

#### Returns

`Uint8Array`

#### Defined in

[protocol/connection-string.ts:19](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/0457b78/packages/wallet-protocol/src/ts/protocol/connection-string.ts#L19)

___

### toString

▸ **toString**(): `string`

#### Returns

`string`

#### Defined in

[protocol/connection-string.ts:6](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/0457b78/packages/wallet-protocol/src/ts/protocol/connection-string.ts#L6)

___

### fromString

▸ `Static` **fromString**(`connString`, `l`): [`ConnectionString`](ConnectionString.md)

#### Parameters

| Name | Type |
| :------ | :------ |
| `connString` | `string` |
| `l` | `number` |

#### Returns

[`ConnectionString`](ConnectionString.md)

#### Defined in

[protocol/connection-string.ts:40](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/0457b78/packages/wallet-protocol/src/ts/protocol/connection-string.ts#L40)

___

### generate

▸ `Static` **generate**(`port`, `l`): `Promise`<[`ConnectionString`](ConnectionString.md)\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `port` | `number` |
| `l` | `number` |

#### Returns

`Promise`<[`ConnectionString`](ConnectionString.md)\>

#### Defined in

[protocol/connection-string.ts:23](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/0457b78/packages/wallet-protocol/src/ts/protocol/connection-string.ts#L23)
