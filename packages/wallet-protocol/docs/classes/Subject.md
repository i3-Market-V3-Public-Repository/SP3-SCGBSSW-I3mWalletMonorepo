# Class: Subject<T\>

## Type parameters

| Name | Type |
| :------ | :------ |
| `T` | `unknown` |

## Table of contents

### Constructors

- [constructor](Subject.md#constructor)

### Properties

- [queue](Subject.md#queue)
- [queueLength](Subject.md#queuelength)
- [rejectPending](Subject.md#rejectpending)
- [resolvePending](Subject.md#resolvepending)

### Accessors

- [promise](Subject.md#promise)

### Methods

- [createPromise](Subject.md#createpromise)
- [err](Subject.md#err)
- [finish](Subject.md#finish)
- [next](Subject.md#next)

## Constructors

### constructor

• **new Subject**<`T`\>(`queueLength?`)

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | `unknown` |

#### Parameters

| Name | Type | Default value |
| :------ | :------ | :------ |
| `queueLength` | `number` | `1` |

#### Defined in

[src/ts/util/subject.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/578e6321/packages/wallet-protocol/src/ts/util/subject.ts#L12)

## Properties

### queue

• `Protected` **queue**: [`Queue`](Queue.md)<`T`\>

#### Defined in

[src/ts/util/subject.ts:8](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/578e6321/packages/wallet-protocol/src/ts/util/subject.ts#L8)

___

### queueLength

• `Readonly` **queueLength**: `number` = `1`

#### Defined in

[src/ts/util/subject.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/578e6321/packages/wallet-protocol/src/ts/util/subject.ts#L12)

___

### rejectPending

• `Protected` `Optional` **rejectPending**: `Rejecter`

#### Defined in

[src/ts/util/subject.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/578e6321/packages/wallet-protocol/src/ts/util/subject.ts#L10)

___

### resolvePending

• `Protected` `Optional` **resolvePending**: `Resolver`<`T`\>

#### Defined in

[src/ts/util/subject.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/578e6321/packages/wallet-protocol/src/ts/util/subject.ts#L9)

## Accessors

### promise

• `get` **promise**(): `Promise`<`T`\>

#### Returns

`Promise`<`T`\>

#### Defined in

[src/ts/util/subject.ts:16](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/578e6321/packages/wallet-protocol/src/ts/util/subject.ts#L16)

## Methods

### createPromise

▸ `Protected` **createPromise**(): `Promise`<`T`\>

#### Returns

`Promise`<`T`\>

#### Defined in

[src/ts/util/subject.ts:20](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/578e6321/packages/wallet-protocol/src/ts/util/subject.ts#L20)

___

### err

▸ **err**(`reason`): `void`

#### Parameters

| Name | Type |
| :------ | :------ |
| `reason` | `any` |

#### Returns

`void`

#### Defined in

[src/ts/util/subject.ts:49](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/578e6321/packages/wallet-protocol/src/ts/util/subject.ts#L49)

___

### finish

▸ **finish**(): `void`

#### Returns

`void`

#### Defined in

[src/ts/util/subject.ts:56](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/578e6321/packages/wallet-protocol/src/ts/util/subject.ts#L56)

___

### next

▸ **next**(`value`): `void`

#### Parameters

| Name | Type |
| :------ | :------ |
| `value` | `T` |

#### Returns

`void`

#### Defined in

[src/ts/util/subject.ts:40](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/578e6321/packages/wallet-protocol/src/ts/util/subject.ts#L40)
