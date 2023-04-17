# Interface: Store<T\>

## Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends `Record`<`string`, `any`\> = `Record`<`string`, `unknown`\> |

## Implemented by

- [`FileStore`](../classes/FileStore.md)
- [`TestStore`](../classes/TestStore.md)

## Table of contents

### Properties

- [clear](Store.md#clear)
- [getPath](Store.md#getpath)
- [getStore](Store.md#getstore)

### Methods

- [delete](Store.md#delete)
- [emit](Store.md#emit)
- [get](Store.md#get)
- [has](Store.md#has)
- [on](Store.md#on)
- [set](Store.md#set)

## Properties

### clear

• **clear**: () => [`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Type declaration

▸ (): [`CanBePromise`](../API.md#canbepromise)<`void`\>

Delete all items.

##### Returns

[`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Defined in

[src/ts/app/store.ts:72](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/733c681/packages/base-wallet/src/ts/app/store.ts#L72)

___

### getPath

• **getPath**: () => `string`

#### Type declaration

▸ (): `string`

Get the path of the store

##### Returns

`string`

The store path

#### Defined in

[src/ts/app/store.ts:84](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/733c681/packages/base-wallet/src/ts/app/store.ts#L84)

___

### getStore

• **getStore**: () => [`CanBePromise`](../API.md#canbepromise)<`T`\>

#### Type declaration

▸ (): [`CanBePromise`](../API.md#canbepromise)<`T`\>

Return a readonly version of the complete store

##### Returns

[`CanBePromise`](../API.md#canbepromise)<`T`\>

The entire store

#### Defined in

[src/ts/app/store.ts:78](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/733c681/packages/base-wallet/src/ts/app/store.ts#L78)

## Methods

### delete

▸ **delete**<`Key`\>(`key`): [`CanBePromise`](../API.md#canbepromise)<`void`\>

Delete an item.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Key` | extends `string` \| `number` \| `symbol` |

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `key` | `Key` | The key of the item to delete. |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Defined in

[src/ts/app/store.ts:66](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/733c681/packages/base-wallet/src/ts/app/store.ts#L66)

▸ **delete**(`key`): [`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `key` | `string` |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Defined in

[src/ts/app/store.ts:67](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/733c681/packages/base-wallet/src/ts/app/store.ts#L67)

___

### emit

▸ **emit**(`eventName`, `changedAt`): `boolean`

Synchronously calls each of the listeners registered for the 'change'
event, in the order they were registered, passing the `changedAt`argument
to each.
The 'change' event should be emitted when the store contents change

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `eventName` | ``"changed"`` |  |
| `changedAt` | `number` | timestamp (in milliseconds ellapsed from EPOCH) when the change happened |

#### Returns

`boolean`

#### Defined in

[src/ts/app/store.ts:151](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/733c681/packages/base-wallet/src/ts/app/store.ts#L151)

▸ **emit**(`eventName`, `changedAt`): `boolean`

Synchronously calls each of the listeners registered for the 'cleared'
event, in the order they were registered, passing the `changedAt`argument
to each.
The 'cleared' event should be emitted when the store contents are cleared.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `eventName` | ``"cleared"`` |  |
| `changedAt` | `number` | timestamp (in milliseconds ellapsed from EPOCH) when the store contents were cleared |

#### Returns

`boolean`

#### Defined in

[src/ts/app/store.ts:161](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/733c681/packages/base-wallet/src/ts/app/store.ts#L161)

▸ **emit**(`eventName`, `...args`): `boolean`

Synchronously calls each of the listeners registered for the event named`eventName`, in the order they were registered, passing the supplied arguments
to each.

Returns `true` if the event had listeners, `false` otherwise.

```js
const EventEmitter = require('events');
const myEmitter = new EventEmitter();

// First listener
myEmitter.on('event', function firstListener() {
  console.log('Helloooo! first listener');
});
// Second listener
myEmitter.on('event', function secondListener(arg1, arg2) {
  console.log(`event with parameters ${arg1}, ${arg2} in second listener`);
});
// Third listener
myEmitter.on('event', function thirdListener(...args) {
  const parameters = args.join(', ');
  console.log(`event with parameters ${parameters} in third listener`);
});

console.log(myEmitter.listeners('event'));

myEmitter.emit('event', 1, 2, 3, 4, 5);

// Prints:
// [
//   [Function: firstListener],
//   [Function: secondListener],
//   [Function: thirdListener]
// ]
// Helloooo! first listener
// event with parameters 1, 2 in second listener
// event with parameters 1, 2, 3, 4, 5 in third listener

#### Parameters

| Name | Type |
| :------ | :------ |
| `eventName` | `string` \| `symbol` |
| `...args` | `any`[] |

#### Returns

`boolean`

#### Defined in

[src/ts/app/store.ts:200](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/733c681/packages/base-wallet/src/ts/app/store.ts#L200)

___

### get

▸ **get**<`Key`\>(`key`): [`CanBePromise`](../API.md#canbepromise)<`T`[`Key`]\>

Get an item.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Key` | extends `string` \| `number` \| `symbol` |

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `key` | `Key` | The key of the item to get. |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`T`[`Key`]\>

#### Defined in

[src/ts/app/store.ts:37](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/733c681/packages/base-wallet/src/ts/app/store.ts#L37)

▸ **get**<`Key`\>(`key`, `defaultValue`): [`CanBePromise`](../API.md#canbepromise)<`Required`<`T`\>[`Key`]\>

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Key` | extends `string` \| `number` \| `symbol` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `key` | `Key` |
| `defaultValue` | `Required`<`T`\>[`Key`] |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`Required`<`T`\>[`Key`]\>

#### Defined in

[src/ts/app/store.ts:38](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/733c681/packages/base-wallet/src/ts/app/store.ts#L38)

___

### has

▸ **has**<`Key`\>(`key`): [`CanBePromise`](../API.md#canbepromise)<`boolean`\>

Check if an item exists.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Key` | extends `string` \| `number` \| `symbol` |

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `key` | `Key` | The key of the item to check. |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`boolean`\>

#### Defined in

[src/ts/app/store.ts:59](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/733c681/packages/base-wallet/src/ts/app/store.ts#L59)

▸ **has**(`key`): [`CanBePromise`](../API.md#canbepromise)<`boolean`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `key` | `string` |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`boolean`\>

#### Defined in

[src/ts/app/store.ts:60](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/733c681/packages/base-wallet/src/ts/app/store.ts#L60)

___

### on

▸ **on**(`eventName`, `listener`): [`Store`](Store.md)<`T`\>

Adds the `listener` function to the end of the listeners array for the
'change' event, which is emitted when the store changes its contents.
The only argument passed to the listener is the `changedAt` timestamp with
the local timestamp (milliseconds ellapsed from EPOCH) when the change happened.
No checks are made to see if the `listener` has already been added. Multiple
calls for the 'change' event will result in multiple `listener` being added,
and called, multiple times when the event is emitted.

#### Parameters

| Name | Type |
| :------ | :------ |
| `eventName` | ``"changed"`` |
| `listener` | (`changedAt`: `number`) => `void` |

#### Returns

[`Store`](Store.md)<`T`\>

#### Defined in

[src/ts/app/store.ts:98](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/733c681/packages/base-wallet/src/ts/app/store.ts#L98)

▸ **on**(`eventName`, `listener`): [`Store`](Store.md)<`T`\>

Adds the `listener` function to the end of the listeners array for the
'cleared' event, which is emitted when the store contents are cleared.
The only argument passed to the listener is the `changedAt` timestamp with
the local timestamp (milliseconds ellapsed from EPOCH) when the change happened.
No checks are made to see if the `listener` has already been added. Multiple
calls for the 'cleared' event will result in multiple `listener` being added,
and called, multiple times when the event is emitted.

#### Parameters

| Name | Type |
| :------ | :------ |
| `eventName` | ``"cleared"`` |
| `listener` | (`changedAt`: `number`) => `void` |

#### Returns

[`Store`](Store.md)<`T`\>

#### Defined in

[src/ts/app/store.ts:111](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/733c681/packages/base-wallet/src/ts/app/store.ts#L111)

▸ **on**(`eventName`, `listener`): [`Store`](Store.md)<`T`\>

Adds a **one-time**`listener` function for the event named `eventName`. The
next time `eventName` is triggered, this listener is removed and then invoked.

```js
server.once('connection', (stream) => {
  console.log('Ah, we have our first user!');
});
```

Returns a reference to the `EventEmitter`, so that calls can be chained.

By default, event listeners are invoked in the order they are added. The`emitter.prependOnceListener()` method can be used as an alternative to add the
event listener to the beginning of the listeners array.

```js
const myEE = new EventEmitter();
myEE.once('foo', () => console.log('a'));
myEE.prependOnceListener('foo', () => console.log('b'));
myEE.emit('foo');
// Prints:
//   b
//   a
```

**`Since`**

v0.3.0

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `eventName` | `string` \| `symbol` | The name of the event. |
| `listener` | (...`args`: `any`[]) => `void` | The callback function |

#### Returns

[`Store`](Store.md)<`T`\>

#### Defined in

[src/ts/app/store.ts:140](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/733c681/packages/base-wallet/src/ts/app/store.ts#L140)

___

### set

▸ **set**(`store`): [`CanBePromise`](../API.md#canbepromise)<`void`\>

Set multiple keys at once.

#### Parameters

| Name | Type |
| :------ | :------ |
| `store` | `Partial`<`T`\> |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Defined in

[src/ts/app/store.ts:44](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/733c681/packages/base-wallet/src/ts/app/store.ts#L44)

▸ **set**<`Key`\>(`key`, `value`): [`CanBePromise`](../API.md#canbepromise)<`void`\>

Set an item.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Key` | extends `string` \| `number` \| `symbol` |

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `key` | `Key` | The key of the item to set |
| `value` | `T`[`Key`] | The value to set |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Defined in

[src/ts/app/store.ts:51](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/733c681/packages/base-wallet/src/ts/app/store.ts#L51)

▸ **set**(`key`, `value`): [`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `key` | `string` |
| `value` | `unknown` |

#### Returns

[`CanBePromise`](../API.md#canbepromise)<`void`\>

#### Defined in

[src/ts/app/store.ts:52](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/733c681/packages/base-wallet/src/ts/app/store.ts#L52)
