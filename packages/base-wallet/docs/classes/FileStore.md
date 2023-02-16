# Class: FileStore<T\>

A class that implements a storage for the wallet in a single file. The server wallet uses a file as storage.

`filepath` is the path to the Wallet's storage file. If you are using a container it should be a path to a file that persists (like one in a volume)

The wallet's storage-file can be encrypted for added security.

## Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends `Record`<`string`, `any`\> = `Record`<`string`, `unknown`\> |

## Hierarchy

- `EventEmitter`

  ↳ **`FileStore`**

## Implements

- [`Store`](../interfaces/Store.md)<`T`\>

## Table of contents

### Constructors

- [constructor](FileStore.md#constructor)

### Properties

- [defaultModel](FileStore.md#defaultmodel)
- [filepath](FileStore.md#filepath)
- [initialized](FileStore.md#initialized)
- [captureRejectionSymbol](FileStore.md#capturerejectionsymbol)
- [captureRejections](FileStore.md#capturerejections)
- [defaultMaxListeners](FileStore.md#defaultmaxlisteners)
- [errorMonitor](FileStore.md#errormonitor)

### Methods

- [addListener](FileStore.md#addlistener)
- [clear](FileStore.md#clear)
- [delete](FileStore.md#delete)
- [deriveKey](FileStore.md#derivekey)
- [emit](FileStore.md#emit)
- [eventNames](FileStore.md#eventnames)
- [get](FileStore.md#get)
- [getMaxListeners](FileStore.md#getmaxlisteners)
- [getPath](FileStore.md#getpath)
- [getStore](FileStore.md#getstore)
- [has](FileStore.md#has)
- [listenerCount](FileStore.md#listenercount)
- [listeners](FileStore.md#listeners)
- [off](FileStore.md#off)
- [on](FileStore.md#on)
- [once](FileStore.md#once)
- [prependListener](FileStore.md#prependlistener)
- [prependOnceListener](FileStore.md#prependoncelistener)
- [rawListeners](FileStore.md#rawlisteners)
- [removeAllListeners](FileStore.md#removealllisteners)
- [removeListener](FileStore.md#removelistener)
- [set](FileStore.md#set)
- [setMaxListeners](FileStore.md#setmaxlisteners)
- [getEventListeners](FileStore.md#geteventlisteners)
- [listenerCount](FileStore.md#listenercount-1)
- [on](FileStore.md#on-1)
- [once](FileStore.md#once-1)
- [setMaxListeners](FileStore.md#setmaxlisteners-1)

## Constructors

### constructor

• **new FileStore**<`T`\>(`filepath`, `keyObject?`, `defaultModel?`)

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends `Record`<`string`, `any`\> = `Record`<`string`, `unknown`\> |

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `filepath` | `string` | an absolute path to the file that will be used to store wallet data |
| `keyObject?` | `KeyObject` | a key object holding a 32 bytes symmetric key to use for encryption/decryption of the storage |
| `defaultModel?` | `T` | - |

#### Overrides

EventEmitter.constructor

#### Defined in

[src/ts/impl/stores/file-store.ts:31](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38c9552/packages/base-wallet/src/ts/impl/stores/file-store.ts#L31)

• **new FileStore**<`T`\>(`filepath`, `password?`, `defaultModel?`)

**`Deprecated`**

you should consider passing a more secure KeyObject derived from your password

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends `Record`<`string`, `any`\> = `Record`<`string`, `unknown`\> |

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `filepath` | `string` | an absolute path to the file that will be used to store wallet data |
| `password?` | `string` | if provided a key will be derived from the password and the store file will be encrypted |
| `defaultModel?` | `T` | - |

#### Overrides

EventEmitter.constructor

#### Defined in

[src/ts/impl/stores/file-store.ts:39](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38c9552/packages/base-wallet/src/ts/impl/stores/file-store.ts#L39)

## Properties

### defaultModel

• **defaultModel**: `T`

#### Defined in

[src/ts/impl/stores/file-store.ts:24](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38c9552/packages/base-wallet/src/ts/impl/stores/file-store.ts#L24)

___

### filepath

• **filepath**: `string`

#### Defined in

[src/ts/impl/stores/file-store.ts:19](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38c9552/packages/base-wallet/src/ts/impl/stores/file-store.ts#L19)

___

### initialized

• **initialized**: `Promise`<`void`\>

#### Defined in

[src/ts/impl/stores/file-store.ts:23](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38c9552/packages/base-wallet/src/ts/impl/stores/file-store.ts#L23)

___

### captureRejectionSymbol

▪ `Static` `Readonly` **captureRejectionSymbol**: typeof [`captureRejectionSymbol`](TestStore.md#capturerejectionsymbol)

#### Inherited from

EventEmitter.captureRejectionSymbol

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:328

___

### captureRejections

▪ `Static` **captureRejections**: `boolean`

Sets or gets the default captureRejection value for all emitters.

#### Inherited from

EventEmitter.captureRejections

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:333

___

### defaultMaxListeners

▪ `Static` **defaultMaxListeners**: `number`

#### Inherited from

EventEmitter.defaultMaxListeners

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:334

___

### errorMonitor

▪ `Static` `Readonly` **errorMonitor**: typeof [`errorMonitor`](TestStore.md#errormonitor)

This symbol shall be used to install a listener for only monitoring `'error'`
events. Listeners installed using this symbol are called before the regular
`'error'` listeners are called.

Installing a listener using this symbol does not change the behavior once an
`'error'` event is emitted, therefore the process will still crash if no
regular `'error'` listener is installed.

#### Inherited from

EventEmitter.errorMonitor

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:327

## Methods

### addListener

▸ **addListener**(`eventName`, `listener`): [`FileStore`](FileStore.md)<`T`\>

Alias for `emitter.on(eventName, listener)`.

**`Since`**

v0.1.26

#### Parameters

| Name | Type |
| :------ | :------ |
| `eventName` | `string` \| `symbol` |
| `listener` | (...`args`: `any`[]) => `void` |

#### Returns

[`FileStore`](FileStore.md)<`T`\>

#### Inherited from

EventEmitter.addListener

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:354

___

### clear

▸ **clear**(): `Promise`<`void`\>

Delete all items.

#### Returns

`Promise`<`void`\>

#### Implementation of

Store.clear

#### Defined in

[src/ts/impl/stores/file-store.ts:211](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38c9552/packages/base-wallet/src/ts/impl/stores/file-store.ts#L211)

___

### delete

▸ **delete**<`Key`\>(`key`): `Promise`<`void`\>

Delete an item.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Key` | extends ``"accounts"`` |

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `key` | `Key` | The key of the item to delete. |

#### Returns

`Promise`<`void`\>

#### Implementation of

[Store](../interfaces/Store.md).[delete](../interfaces/Store.md#delete)

#### Defined in

[src/ts/impl/stores/file-store.ts:202](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38c9552/packages/base-wallet/src/ts/impl/stores/file-store.ts#L202)

___

### deriveKey

▸ **deriveKey**(`password`, `salt?`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `password` | `string` |
| `salt?` | `Buffer` |

#### Returns

`Promise`<`void`\>

#### Defined in

[src/ts/impl/stores/file-store.ts:82](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38c9552/packages/base-wallet/src/ts/impl/stores/file-store.ts#L82)

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

#### Implementation of

[Store](../interfaces/Store.md).[emit](../interfaces/Store.md#emit)

#### Overrides

EventEmitter.emit

#### Defined in

[src/ts/impl/stores/file-store.ts:65](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38c9552/packages/base-wallet/src/ts/impl/stores/file-store.ts#L65)

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

#### Implementation of

[Store](../interfaces/Store.md).[emit](../interfaces/Store.md#emit)

#### Overrides

EventEmitter.emit

#### Defined in

[src/ts/impl/stores/file-store.ts:66](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38c9552/packages/base-wallet/src/ts/impl/stores/file-store.ts#L66)

▸ **emit**(`eventName`, ...`args`): `boolean`

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

#### Implementation of

[Store](../interfaces/Store.md).[emit](../interfaces/Store.md#emit)

#### Overrides

EventEmitter.emit

#### Defined in

[src/ts/impl/stores/file-store.ts:67](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38c9552/packages/base-wallet/src/ts/impl/stores/file-store.ts#L67)

___

### eventNames

▸ **eventNames**(): (`string` \| `symbol`)[]

Returns an array listing the events for which the emitter has registered
listeners. The values in the array are strings or `Symbol`s.

```js
const EventEmitter = require('events');
const myEE = new EventEmitter();
myEE.on('foo', () => {});
myEE.on('bar', () => {});

const sym = Symbol('symbol');
myEE.on(sym, () => {});

console.log(myEE.eventNames());
// Prints: [ 'foo', 'bar', Symbol(symbol) ]
```

**`Since`**

v6.0.0

#### Returns

(`string` \| `symbol`)[]

#### Inherited from

EventEmitter.eventNames

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:669

___

### get

▸ **get**(`key`, `defaultValue?`): `Promise`<`any`\>

Get an item.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `key` | `any` | The key of the item to get. |
| `defaultValue?` | `any` | - |

#### Returns

`Promise`<`any`\>

#### Implementation of

[Store](../interfaces/Store.md).[get](../interfaces/Store.md#get)

#### Defined in

[src/ts/impl/stores/file-store.ts:174](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38c9552/packages/base-wallet/src/ts/impl/stores/file-store.ts#L174)

___

### getMaxListeners

▸ **getMaxListeners**(): `number`

Returns the current max listener value for the `EventEmitter` which is either
set by `emitter.setMaxListeners(n)` or defaults to [defaultMaxListeners](FileStore.md#defaultmaxlisteners).

**`Since`**

v1.0.0

#### Returns

`number`

#### Inherited from

EventEmitter.getMaxListeners

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:526

___

### getPath

▸ **getPath**(): `string`

Get the path of the store

#### Returns

`string`

The store path

#### Implementation of

Store.getPath

#### Defined in

[src/ts/impl/stores/file-store.ts:224](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38c9552/packages/base-wallet/src/ts/impl/stores/file-store.ts#L224)

___

### getStore

▸ **getStore**(): `Promise`<`T`\>

Return a readonly version of the complete store

#### Returns

`Promise`<`T`\>

The entire store

#### Implementation of

Store.getStore

#### Defined in

[src/ts/impl/stores/file-store.ts:218](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38c9552/packages/base-wallet/src/ts/impl/stores/file-store.ts#L218)

___

### has

▸ **has**<`Key`\>(`key`): `Promise`<`boolean`\>

Check if an item exists.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Key` | extends ``"accounts"`` |

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `key` | `Key` | The key of the item to check. |

#### Returns

`Promise`<`boolean`\>

#### Implementation of

[Store](../interfaces/Store.md).[has](../interfaces/Store.md#has)

#### Defined in

[src/ts/impl/stores/file-store.ts:195](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38c9552/packages/base-wallet/src/ts/impl/stores/file-store.ts#L195)

___

### listenerCount

▸ **listenerCount**(`eventName`): `number`

Returns the number of listeners listening to the event named `eventName`.

**`Since`**

v3.2.0

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `eventName` | `string` \| `symbol` | The name of the event being listened for |

#### Returns

`number`

#### Inherited from

EventEmitter.listenerCount

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:616

___

### listeners

▸ **listeners**(`eventName`): `Function`[]

Returns a copy of the array of listeners for the event named `eventName`.

```js
server.on('connection', (stream) => {
  console.log('someone connected!');
});
console.log(util.inspect(server.listeners('connection')));
// Prints: [ [Function] ]
```

**`Since`**

v0.1.26

#### Parameters

| Name | Type |
| :------ | :------ |
| `eventName` | `string` \| `symbol` |

#### Returns

`Function`[]

#### Inherited from

EventEmitter.listeners

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:539

___

### off

▸ **off**(`eventName`, `listener`): [`FileStore`](FileStore.md)<`T`\>

Alias for `emitter.removeListener()`.

**`Since`**

v10.0.0

#### Parameters

| Name | Type |
| :------ | :------ |
| `eventName` | `string` \| `symbol` |
| `listener` | (...`args`: `any`[]) => `void` |

#### Returns

[`FileStore`](FileStore.md)<`T`\>

#### Inherited from

EventEmitter.off

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:499

___

### on

▸ **on**(`eventName`, `listener`): [`FileStore`](FileStore.md)<`T`\>

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

[`FileStore`](FileStore.md)<`T`\>

#### Implementation of

[Store](../interfaces/Store.md).[on](../interfaces/Store.md#on)

#### Overrides

EventEmitter.on

#### Defined in

[src/ts/impl/stores/file-store.ts:58](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38c9552/packages/base-wallet/src/ts/impl/stores/file-store.ts#L58)

▸ **on**(`eventName`, `listener`): [`FileStore`](FileStore.md)<`T`\>

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

[`FileStore`](FileStore.md)<`T`\>

#### Implementation of

[Store](../interfaces/Store.md).[on](../interfaces/Store.md#on)

#### Overrides

EventEmitter.on

#### Defined in

[src/ts/impl/stores/file-store.ts:59](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38c9552/packages/base-wallet/src/ts/impl/stores/file-store.ts#L59)

▸ **on**(`eventName`, `listener`): [`FileStore`](FileStore.md)<`T`\>

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

[`FileStore`](FileStore.md)<`T`\>

#### Implementation of

[Store](../interfaces/Store.md).[on](../interfaces/Store.md#on)

#### Overrides

EventEmitter.on

#### Defined in

[src/ts/impl/stores/file-store.ts:60](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38c9552/packages/base-wallet/src/ts/impl/stores/file-store.ts#L60)

___

### once

▸ **once**(`eventName`, `listener`): [`FileStore`](FileStore.md)<`T`\>

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

[`FileStore`](FileStore.md)<`T`\>

#### Inherited from

EventEmitter.once

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:414

___

### prependListener

▸ **prependListener**(`eventName`, `listener`): [`FileStore`](FileStore.md)<`T`\>

Adds the `listener` function to the _beginning_ of the listeners array for the
event named `eventName`. No checks are made to see if the `listener` has
already been added. Multiple calls passing the same combination of `eventName`and `listener` will result in the `listener` being added, and called, multiple
times.

```js
server.prependListener('connection', (stream) => {
  console.log('someone connected!');
});
```

Returns a reference to the `EventEmitter`, so that calls can be chained.

**`Since`**

v6.0.0

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `eventName` | `string` \| `symbol` | The name of the event. |
| `listener` | (...`args`: `any`[]) => `void` | The callback function |

#### Returns

[`FileStore`](FileStore.md)<`T`\>

#### Inherited from

EventEmitter.prependListener

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:634

___

### prependOnceListener

▸ **prependOnceListener**(`eventName`, `listener`): [`FileStore`](FileStore.md)<`T`\>

Adds a **one-time**`listener` function for the event named `eventName` to the _beginning_ of the listeners array. The next time `eventName` is triggered, this
listener is removed, and then invoked.

```js
server.prependOnceListener('connection', (stream) => {
  console.log('Ah, we have our first user!');
});
```

Returns a reference to the `EventEmitter`, so that calls can be chained.

**`Since`**

v6.0.0

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `eventName` | `string` \| `symbol` | The name of the event. |
| `listener` | (...`args`: `any`[]) => `void` | The callback function |

#### Returns

[`FileStore`](FileStore.md)<`T`\>

#### Inherited from

EventEmitter.prependOnceListener

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:650

___

### rawListeners

▸ **rawListeners**(`eventName`): `Function`[]

Returns a copy of the array of listeners for the event named `eventName`,
including any wrappers (such as those created by `.once()`).

```js
const emitter = new EventEmitter();
emitter.once('log', () => console.log('log once'));

// Returns a new Array with a function `onceWrapper` which has a property
// `listener` which contains the original listener bound above
const listeners = emitter.rawListeners('log');
const logFnWrapper = listeners[0];

// Logs "log once" to the console and does not unbind the `once` event
logFnWrapper.listener();

// Logs "log once" to the console and removes the listener
logFnWrapper();

emitter.on('log', () => console.log('log persistently'));
// Will return a new Array with a single function bound by `.on()` above
const newListeners = emitter.rawListeners('log');

// Logs "log persistently" twice
newListeners[0]();
emitter.emit('log');
```

**`Since`**

v9.4.0

#### Parameters

| Name | Type |
| :------ | :------ |
| `eventName` | `string` \| `symbol` |

#### Returns

`Function`[]

#### Inherited from

EventEmitter.rawListeners

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:569

___

### removeAllListeners

▸ **removeAllListeners**(`event?`): [`FileStore`](FileStore.md)<`T`\>

Removes all listeners, or those of the specified `eventName`.

It is bad practice to remove listeners added elsewhere in the code,
particularly when the `EventEmitter` instance was created by some other
component or module (e.g. sockets or file streams).

Returns a reference to the `EventEmitter`, so that calls can be chained.

**`Since`**

v0.1.26

#### Parameters

| Name | Type |
| :------ | :------ |
| `event?` | `string` \| `symbol` |

#### Returns

[`FileStore`](FileStore.md)<`T`\>

#### Inherited from

EventEmitter.removeAllListeners

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:510

___

### removeListener

▸ **removeListener**(`eventName`, `listener`): [`FileStore`](FileStore.md)<`T`\>

Removes the specified `listener` from the listener array for the event named`eventName`.

```js
const callback = (stream) => {
  console.log('someone connected!');
};
server.on('connection', callback);
// ...
server.removeListener('connection', callback);
```

`removeListener()` will remove, at most, one instance of a listener from the
listener array. If any single listener has been added multiple times to the
listener array for the specified `eventName`, then `removeListener()` must be
called multiple times to remove each instance.

Once an event is emitted, all listeners attached to it at the
time of emitting are called in order. This implies that any`removeListener()` or `removeAllListeners()` calls _after_ emitting and _before_ the last listener finishes execution
will not remove them from`emit()` in progress. Subsequent events behave as expected.

```js
const myEmitter = new MyEmitter();

const callbackA = () => {
  console.log('A');
  myEmitter.removeListener('event', callbackB);
};

const callbackB = () => {
  console.log('B');
};

myEmitter.on('event', callbackA);

myEmitter.on('event', callbackB);

// callbackA removes listener callbackB but it will still be called.
// Internal listener array at time of emit [callbackA, callbackB]
myEmitter.emit('event');
// Prints:
//   A
//   B

// callbackB is now removed.
// Internal listener array [callbackA]
myEmitter.emit('event');
// Prints:
//   A
```

Because listeners are managed using an internal array, calling this will
change the position indices of any listener registered _after_ the listener
being removed. This will not impact the order in which listeners are called,
but it means that any copies of the listener array as returned by
the `emitter.listeners()` method will need to be recreated.

When a single function has been added as a handler multiple times for a single
event (as in the example below), `removeListener()` will remove the most
recently added instance. In the example the `once('ping')`listener is removed:

```js
const ee = new EventEmitter();

function pong() {
  console.log('pong');
}

ee.on('ping', pong);
ee.once('ping', pong);
ee.removeListener('ping', pong);

ee.emit('ping');
ee.emit('ping');
```

Returns a reference to the `EventEmitter`, so that calls can be chained.

**`Since`**

v0.1.26

#### Parameters

| Name | Type |
| :------ | :------ |
| `eventName` | `string` \| `symbol` |
| `listener` | (...`args`: `any`[]) => `void` |

#### Returns

[`FileStore`](FileStore.md)<`T`\>

#### Inherited from

EventEmitter.removeListener

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:494

___

### set

▸ **set**(`keyOrStore`, `value?`): `Promise`<`void`\>

Set multiple keys at once.

#### Parameters

| Name | Type |
| :------ | :------ |
| `keyOrStore` | `any` |
| `value?` | `any` |

#### Returns

`Promise`<`void`\>

#### Implementation of

[Store](../interfaces/Store.md).[set](../interfaces/Store.md#set)

#### Defined in

[src/ts/impl/stores/file-store.ts:181](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38c9552/packages/base-wallet/src/ts/impl/stores/file-store.ts#L181)

___

### setMaxListeners

▸ **setMaxListeners**(`n`): [`FileStore`](FileStore.md)<`T`\>

By default `EventEmitter`s will print a warning if more than `10` listeners are
added for a particular event. This is a useful default that helps finding
memory leaks. The `emitter.setMaxListeners()` method allows the limit to be
modified for this specific `EventEmitter` instance. The value can be set to`Infinity` (or `0`) to indicate an unlimited number of listeners.

Returns a reference to the `EventEmitter`, so that calls can be chained.

**`Since`**

v0.3.5

#### Parameters

| Name | Type |
| :------ | :------ |
| `n` | `number` |

#### Returns

[`FileStore`](FileStore.md)<`T`\>

#### Inherited from

EventEmitter.setMaxListeners

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:520

___

### getEventListeners

▸ `Static` **getEventListeners**(`emitter`, `name`): `Function`[]

Returns a copy of the array of listeners for the event named `eventName`.

For `EventEmitter`s this behaves exactly the same as calling `.listeners` on
the emitter.

For `EventTarget`s this is the only way to get the event listeners for the
event target. This is useful for debugging and diagnostic purposes.

```js
const { getEventListeners, EventEmitter } = require('events');

{
  const ee = new EventEmitter();
  const listener = () => console.log('Events are fun');
  ee.on('foo', listener);
  getEventListeners(ee, 'foo'); // [listener]
}
{
  const et = new EventTarget();
  const listener = () => console.log('Events are fun');
  et.addEventListener('foo', listener);
  getEventListeners(et, 'foo'); // [listener]
}
```

**`Since`**

v15.2.0, v14.17.0

#### Parameters

| Name | Type |
| :------ | :------ |
| `emitter` | `EventEmitter` \| `_DOMEventTarget` |
| `name` | `string` \| `symbol` |

#### Returns

`Function`[]

#### Inherited from

EventEmitter.getEventListeners

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:299

___

### listenerCount

▸ `Static` **listenerCount**(`emitter`, `eventName`): `number`

A class method that returns the number of listeners for the given `eventName`registered on the given `emitter`.

```js
const { EventEmitter, listenerCount } = require('events');
const myEmitter = new EventEmitter();
myEmitter.on('event', () => {});
myEmitter.on('event', () => {});
console.log(listenerCount(myEmitter, 'event'));
// Prints: 2
```

**`Since`**

v0.9.12

**`Deprecated`**

Since v3.2.0 - Use `listenerCount` instead.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `emitter` | `EventEmitter` | The emitter to query |
| `eventName` | `string` \| `symbol` | The event name |

#### Returns

`number`

#### Inherited from

EventEmitter.listenerCount

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:271

___

### on

▸ `Static` **on**(`emitter`, `eventName`, `options?`): `AsyncIterableIterator`<`any`\>

```js
const { on, EventEmitter } = require('events');

(async () => {
  const ee = new EventEmitter();

  // Emit later on
  process.nextTick(() => {
    ee.emit('foo', 'bar');
    ee.emit('foo', 42);
  });

  for await (const event of on(ee, 'foo')) {
    // The execution of this inner block is synchronous and it
    // processes one event at a time (even with await). Do not use
    // if concurrent execution is required.
    console.log(event); // prints ['bar'] [42]
  }
  // Unreachable here
})();
```

Returns an `AsyncIterator` that iterates `eventName` events. It will throw
if the `EventEmitter` emits `'error'`. It removes all listeners when
exiting the loop. The `value` returned by each iteration is an array
composed of the emitted event arguments.

An `AbortSignal` can be used to cancel waiting on events:

```js
const { on, EventEmitter } = require('events');
const ac = new AbortController();

(async () => {
  const ee = new EventEmitter();

  // Emit later on
  process.nextTick(() => {
    ee.emit('foo', 'bar');
    ee.emit('foo', 42);
  });

  for await (const event of on(ee, 'foo', { signal: ac.signal })) {
    // The execution of this inner block is synchronous and it
    // processes one event at a time (even with await). Do not use
    // if concurrent execution is required.
    console.log(event); // prints ['bar'] [42]
  }
  // Unreachable here
})();

process.nextTick(() => ac.abort());
```

**`Since`**

v13.6.0, v12.16.0

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `emitter` | `EventEmitter` | - |
| `eventName` | `string` | The name of the event being listened for |
| `options?` | `StaticEventEmitterOptions` | - |

#### Returns

`AsyncIterableIterator`<`any`\>

that iterates `eventName` events emitted by the `emitter`

#### Inherited from

EventEmitter.on

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:254

___

### once

▸ `Static` **once**(`emitter`, `eventName`, `options?`): `Promise`<`any`[]\>

Creates a `Promise` that is fulfilled when the `EventEmitter` emits the given
event or that is rejected if the `EventEmitter` emits `'error'` while waiting.
The `Promise` will resolve with an array of all the arguments emitted to the
given event.

This method is intentionally generic and works with the web platform [EventTarget](https://dom.spec.whatwg.org/#interface-eventtarget) interface, which has no special`'error'` event
semantics and does not listen to the `'error'` event.

```js
const { once, EventEmitter } = require('events');

async function run() {
  const ee = new EventEmitter();

  process.nextTick(() => {
    ee.emit('myevent', 42);
  });

  const [value] = await once(ee, 'myevent');
  console.log(value);

  const err = new Error('kaboom');
  process.nextTick(() => {
    ee.emit('error', err);
  });

  try {
    await once(ee, 'myevent');
  } catch (err) {
    console.log('error happened', err);
  }
}

run();
```

The special handling of the `'error'` event is only used when `events.once()`is used to wait for another event. If `events.once()` is used to wait for the
'`error'` event itself, then it is treated as any other kind of event without
special handling:

```js
const { EventEmitter, once } = require('events');

const ee = new EventEmitter();

once(ee, 'error')
  .then(([err]) => console.log('ok', err.message))
  .catch((err) => console.log('error', err.message));

ee.emit('error', new Error('boom'));

// Prints: ok boom
```

An `AbortSignal` can be used to cancel waiting for the event:

```js
const { EventEmitter, once } = require('events');

const ee = new EventEmitter();
const ac = new AbortController();

async function foo(emitter, event, signal) {
  try {
    await once(emitter, event, { signal });
    console.log('event emitted!');
  } catch (error) {
    if (error.name === 'AbortError') {
      console.error('Waiting for the event was canceled!');
    } else {
      console.error('There was an error', error.message);
    }
  }
}

foo(ee, 'foo', ac.signal);
ac.abort(); // Abort waiting for the event
ee.emit('foo'); // Prints: Waiting for the event was canceled!
```

**`Since`**

v11.13.0, v10.16.0

#### Parameters

| Name | Type |
| :------ | :------ |
| `emitter` | `_NodeEventTarget` |
| `eventName` | `string` \| `symbol` |
| `options?` | `StaticEventEmitterOptions` |

#### Returns

`Promise`<`any`[]\>

#### Inherited from

EventEmitter.once

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:194

▸ `Static` **once**(`emitter`, `eventName`, `options?`): `Promise`<`any`[]\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `emitter` | `_DOMEventTarget` |
| `eventName` | `string` |
| `options?` | `StaticEventEmitterOptions` |

#### Returns

`Promise`<`any`[]\>

#### Inherited from

EventEmitter.once

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:195

___

### setMaxListeners

▸ `Static` **setMaxListeners**(`n?`, ...`eventTargets`): `void`

```js
const {
  setMaxListeners,
  EventEmitter
} = require('events');

const target = new EventTarget();
const emitter = new EventEmitter();

setMaxListeners(5, target, emitter);
```

**`Since`**

v15.4.0

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `n?` | `number` | A non-negative number. The maximum number of listeners per `EventTarget` event. |
| `...eventTargets` | (`EventEmitter` \| `_DOMEventTarget`)[] | - |

#### Returns

`void`

#### Inherited from

EventEmitter.setMaxListeners

#### Defined in

node_modules/@types/node/ts4.8/events.d.ts:317
