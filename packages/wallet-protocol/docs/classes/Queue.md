# Class: Queue<T\>

## Type parameters

| Name |
| :------ |
| `T` |

## Table of contents

### Constructors

- [constructor](Queue.md#constructor)

### Properties

- [\_first](Queue.md#_first)
- [\_length](Queue.md#_length)
- [\_values](Queue.md#_values)
- [maxLength](Queue.md#maxlength)

### Accessors

- [last](Queue.md#last)
- [length](Queue.md#length)

### Methods

- [pop](Queue.md#pop)
- [push](Queue.md#push)

## Constructors

### constructor

• **new Queue**<`T`\>(`maxLength`)

#### Type parameters

| Name |
| :------ |
| `T` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `maxLength` | `number` |

#### Defined in

[src/ts/util/queue.ts:7](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/util/queue.ts#L7)

## Properties

### \_first

• `Protected` **\_first**: `number`

#### Defined in

[src/ts/util/queue.ts:4](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/util/queue.ts#L4)

___

### \_length

• `Protected` **\_length**: `number`

#### Defined in

[src/ts/util/queue.ts:5](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/util/queue.ts#L5)

___

### \_values

• `Protected` **\_values**: `T`[]

#### Defined in

[src/ts/util/queue.ts:3](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/util/queue.ts#L3)

___

### maxLength

• `Readonly` **maxLength**: `number`

#### Defined in

[src/ts/util/queue.ts:7](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/util/queue.ts#L7)

## Accessors

### last

• `get` **last**(): `undefined` \| `T`

#### Returns

`undefined` \| `T`

#### Defined in

[src/ts/util/queue.ts:40](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/util/queue.ts#L40)

___

### length

• `get` **length**(): `number`

#### Returns

`number`

#### Defined in

[src/ts/util/queue.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/util/queue.ts#L13)

## Methods

### pop

▸ **pop**(): `undefined` \| `T`

#### Returns

`undefined` \| `T`

#### Defined in

[src/ts/util/queue.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/util/queue.ts#L26)

___

### push

▸ **push**(`value`): `void`

#### Parameters

| Name | Type |
| :------ | :------ |
| `value` | `T` |

#### Returns

`void`

#### Defined in

[src/ts/util/queue.ts:17](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/8755ad1b/packages/wallet-protocol/src/ts/util/queue.ts#L17)
