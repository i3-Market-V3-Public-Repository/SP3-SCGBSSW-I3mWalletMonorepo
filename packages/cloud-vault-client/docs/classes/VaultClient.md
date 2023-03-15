# Class: VaultClient

## Hierarchy

- `EventEmitter`

  ↳ **`VaultClient`**

## Table of contents

### Constructors

- [constructor](VaultClient.md#constructor)

### Properties

- [name](VaultClient.md#name)
- [opts](VaultClient.md#opts)
- [serverUrl](VaultClient.md#serverurl)
- [timestamp](VaultClient.md#timestamp)
- [token](VaultClient.md#token)
- [wellKnownCvsConfiguration](VaultClient.md#wellknowncvsconfiguration)
- [captureRejectionSymbol](VaultClient.md#capturerejectionsymbol)
- [captureRejections](VaultClient.md#capturerejections)
- [defaultMaxListeners](VaultClient.md#defaultmaxlisteners)
- [errorMonitor](VaultClient.md#errormonitor)

### Accessors

- [initialized](VaultClient.md#initialized)
- [state](VaultClient.md#state)

### Methods

- [addListener](VaultClient.md#addlistener)
- [close](VaultClient.md#close)
- [deleteStorage](VaultClient.md#deletestorage)
- [emit](VaultClient.md#emit)
- [eventNames](VaultClient.md#eventnames)
- [getMaxListeners](VaultClient.md#getmaxlisteners)
- [getRemoteStorageTimestamp](VaultClient.md#getremotestoragetimestamp)
- [getServerPublicKey](VaultClient.md#getserverpublickey)
- [getStorage](VaultClient.md#getstorage)
- [listenerCount](VaultClient.md#listenercount)
- [listeners](VaultClient.md#listeners)
- [login](VaultClient.md#login)
- [logout](VaultClient.md#logout)
- [off](VaultClient.md#off)
- [on](VaultClient.md#on)
- [once](VaultClient.md#once)
- [prependListener](VaultClient.md#prependlistener)
- [prependOnceListener](VaultClient.md#prependoncelistener)
- [rawListeners](VaultClient.md#rawlisteners)
- [removeAllListeners](VaultClient.md#removealllisteners)
- [removeListener](VaultClient.md#removelistener)
- [setMaxListeners](VaultClient.md#setmaxlisteners)
- [updateStorage](VaultClient.md#updatestorage)
- [computeAuthKey](VaultClient.md#computeauthkey)
- [getEventListeners](VaultClient.md#geteventlisteners)
- [getWellKnownCvsConfiguration](VaultClient.md#getwellknowncvsconfiguration)
- [listenerCount](VaultClient.md#listenercount-1)
- [on](VaultClient.md#on-1)
- [once](VaultClient.md#once-1)
- [setMaxListeners](VaultClient.md#setmaxlisteners-1)

## Constructors

### constructor

• **new VaultClient**(`serverUrl`, `opts?`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `serverUrl` | `string` |
| `opts?` | [`VaultClientOpts`](../interfaces/VaultClientOpts.md) |

#### Overrides

EventEmitter.constructor

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:48](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L48)

## Properties

### name

• **name**: `string`

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:29](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L29)

___

### opts

• `Optional` **opts**: [`VaultClientOpts`](../interfaces/VaultClientOpts.md)

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:30](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L30)

___

### serverUrl

• **serverUrl**: `string`

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:31](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L31)

___

### timestamp

• `Optional` **timestamp**: `number`

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:27](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L27)

___

### token

• `Optional` **token**: `string`

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:28](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L28)

___

### wellKnownCvsConfiguration

• `Optional` **wellKnownCvsConfiguration**: `CvsConfiguration`

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:38](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L38)

___

### captureRejectionSymbol

▪ `Static` `Readonly` **captureRejectionSymbol**: typeof [`captureRejectionSymbol`](VaultClient.md#capturerejectionsymbol)

#### Inherited from

EventEmitter.captureRejectionSymbol

#### Defined in

cloud-vault-client/node_modules/@types/node/events.d.ts:328

___

### captureRejections

▪ `Static` **captureRejections**: `boolean`

Sets or gets the default captureRejection value for all emitters.

#### Inherited from

EventEmitter.captureRejections

#### Defined in

cloud-vault-client/node_modules/@types/node/events.d.ts:333

___

### defaultMaxListeners

▪ `Static` **defaultMaxListeners**: `number`

#### Inherited from

EventEmitter.defaultMaxListeners

#### Defined in

cloud-vault-client/node_modules/@types/node/events.d.ts:334

___

### errorMonitor

▪ `Static` `Readonly` **errorMonitor**: typeof [`errorMonitor`](VaultClient.md#errormonitor)

This symbol shall be used to install a listener for only monitoring `'error'`
events. Listeners installed using this symbol are called before the regular
`'error'` listeners are called.

Installing a listener using this symbol does not change the behavior once an
`'error'` event is emitted, therefore the process will still crash if no
regular `'error'` listener is installed.

#### Inherited from

EventEmitter.errorMonitor

#### Defined in

cloud-vault-client/node_modules/@types/node/events.d.ts:327

## Accessors

### initialized

• `get` **initialized**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:60](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L60)

___

### state

• `get` **state**(): [`VaultState`](../API.md#vaultstate)

#### Returns

[`VaultState`](../API.md#vaultstate)

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:74](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L74)

• `set` **state**(`newState`): `void`

#### Parameters

| Name | Type |
| :------ | :------ |
| `newState` | [`VaultState`](../API.md#vaultstate) |

#### Returns

`void`

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:78](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L78)

## Methods

### addListener

▸ **addListener**(`eventName`, `listener`): [`VaultClient`](VaultClient.md)

Alias for `emitter.on(eventName, listener)`.

**`Since`**

v0.1.26

#### Parameters

| Name | Type |
| :------ | :------ |
| `eventName` | `string` \| `symbol` |
| `listener` | (...`args`: `any`[]) => `void` |

#### Returns

[`VaultClient`](VaultClient.md)

#### Inherited from

EventEmitter.addListener

#### Defined in

cloud-vault-client/node_modules/@types/node/events.d.ts:354

___

### close

▸ **close**(): `void`

#### Returns

`void`

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:204](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L204)

___

### deleteStorage

▸ **deleteStorage**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:361](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L361)

___

### emit

▸ **emit**<`T`\>(`eventName`, `...args`): `boolean`

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends keyof `VaultEvent` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `eventName` | `T` |
| `...args` | `ArgsForEvent`<`T`\> |

#### Returns

`boolean`

#### Overrides

EventEmitter.emit

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:115](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L115)

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

cloud-vault-client/node_modules/@types/node/events.d.ts:669

___

### getMaxListeners

▸ **getMaxListeners**(): `number`

Returns the current max listener value for the `EventEmitter` which is either
set by `emitter.setMaxListeners(n)` or defaults to [defaultMaxListeners](VaultClient.md#defaultmaxlisteners).

**`Since`**

v1.0.0

#### Returns

`number`

#### Inherited from

EventEmitter.getMaxListeners

#### Defined in

cloud-vault-client/node_modules/@types/node/events.d.ts:526

___

### getRemoteStorageTimestamp

▸ **getRemoteStorageTimestamp**(): `Promise`<``null`` \| `number`\>

#### Returns

`Promise`<``null`` \| `number`\>

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:249](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L249)

___

### getServerPublicKey

▸ **getServerPublicKey**(): `Promise`<`JwkEcPublicKey`\>

#### Returns

`Promise`<`JwkEcPublicKey`\>

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:384](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L384)

___

### getStorage

▸ **getStorage**(): `Promise`<[`VaultStorage`](../interfaces/VaultStorage.md)\>

#### Returns

`Promise`<[`VaultStorage`](../interfaces/VaultStorage.md)\>

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:276](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L276)

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

cloud-vault-client/node_modules/@types/node/events.d.ts:616

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

cloud-vault-client/node_modules/@types/node/events.d.ts:539

___

### login

▸ **login**(`username`, `password`, `timestamp?`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `username` | `string` |
| `password` | `string` |
| `timestamp?` | `number` |

#### Returns

`Promise`<`void`\>

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:211](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L211)

___

### logout

▸ **logout**(): `void`

#### Returns

`void`

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:196](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L196)

___

### off

▸ **off**(`eventName`, `listener`): [`VaultClient`](VaultClient.md)

Alias for `emitter.removeListener()`.

**`Since`**

v10.0.0

#### Parameters

| Name | Type |
| :------ | :------ |
| `eventName` | `string` \| `symbol` |
| `listener` | (...`args`: `any`[]) => `void` |

#### Returns

[`VaultClient`](VaultClient.md)

#### Inherited from

EventEmitter.off

#### Defined in

cloud-vault-client/node_modules/@types/node/events.d.ts:499

___

### on

▸ **on**<`T`\>(`event`, `cb`): [`VaultClient`](VaultClient.md)

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends keyof `VaultEvent` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `event` | `T` |
| `cb` | [`CbOnEventFn`](../API.md#cboneventfn)<`T`\> |

#### Returns

[`VaultClient`](VaultClient.md)

#### Overrides

EventEmitter.on

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:120](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L120)

___

### once

▸ **once**<`T`\>(`event`, `cb`): [`VaultClient`](VaultClient.md)

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends keyof `VaultEvent` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `event` | `T` |
| `cb` | [`CbOnEventFn`](../API.md#cboneventfn)<`T`\> |

#### Returns

[`VaultClient`](VaultClient.md)

#### Overrides

EventEmitter.once

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:125](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L125)

___

### prependListener

▸ **prependListener**(`eventName`, `listener`): [`VaultClient`](VaultClient.md)

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

[`VaultClient`](VaultClient.md)

#### Inherited from

EventEmitter.prependListener

#### Defined in

cloud-vault-client/node_modules/@types/node/events.d.ts:634

___

### prependOnceListener

▸ **prependOnceListener**(`eventName`, `listener`): [`VaultClient`](VaultClient.md)

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

[`VaultClient`](VaultClient.md)

#### Inherited from

EventEmitter.prependOnceListener

#### Defined in

cloud-vault-client/node_modules/@types/node/events.d.ts:650

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

cloud-vault-client/node_modules/@types/node/events.d.ts:569

___

### removeAllListeners

▸ **removeAllListeners**(`event?`): [`VaultClient`](VaultClient.md)

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

[`VaultClient`](VaultClient.md)

#### Inherited from

EventEmitter.removeAllListeners

#### Defined in

cloud-vault-client/node_modules/@types/node/events.d.ts:510

___

### removeListener

▸ **removeListener**(`eventName`, `listener`): [`VaultClient`](VaultClient.md)

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

[`VaultClient`](VaultClient.md)

#### Inherited from

EventEmitter.removeListener

#### Defined in

cloud-vault-client/node_modules/@types/node/events.d.ts:494

___

### setMaxListeners

▸ **setMaxListeners**(`n`): [`VaultClient`](VaultClient.md)

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

[`VaultClient`](VaultClient.md)

#### Inherited from

EventEmitter.setMaxListeners

#### Defined in

cloud-vault-client/node_modules/@types/node/events.d.ts:520

___

### updateStorage

▸ **updateStorage**(`storage`, `force?`, `retryOptions?`): `Promise`<`number`\>

#### Parameters

| Name | Type | Default value |
| :------ | :------ | :------ |
| `storage` | [`VaultStorage`](../interfaces/VaultStorage.md) | `undefined` |
| `force` | `boolean` | `false` |
| `retryOptions?` | [`RetryOptions`](../interfaces/RetryOptions.md) | `undefined` |

#### Returns

`Promise`<`number`\>

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:316](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L316)

___

### computeAuthKey

▸ `Static` **computeAuthKey**(`serverUrl`, `username`, `password`, `retryOptions?`): `Promise`<`string`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `serverUrl` | `string` |
| `username` | `string` |
| `password` | `string` |
| `retryOptions?` | [`RetryOptions`](../interfaces/RetryOptions.md) |

#### Returns

`Promise`<`string`\>

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:409](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L409)

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

cloud-vault-client/node_modules/@types/node/events.d.ts:299

___

### getWellKnownCvsConfiguration

▸ `Static` **getWellKnownCvsConfiguration**(`serverUrl`, `opts?`): `Object`

#### Parameters

| Name | Type |
| :------ | :------ |
| `serverUrl` | `string` |
| `opts?` | [`RetryOptions`](../interfaces/RetryOptions.md) |

#### Returns

`Object`

| Name | Type |
| :------ | :------ |
| `promise` | `Promise`<`CvsConfiguration`\> |
| `stop` | () => `Promise`<`void`\> |

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:395](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/vault-client.ts#L395)

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

cloud-vault-client/node_modules/@types/node/events.d.ts:271

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

cloud-vault-client/node_modules/@types/node/events.d.ts:254

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

cloud-vault-client/node_modules/@types/node/events.d.ts:194

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

cloud-vault-client/node_modules/@types/node/events.d.ts:195

___

### setMaxListeners

▸ `Static` **setMaxListeners**(`n?`, `...eventTargets`): `void`

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

cloud-vault-client/node_modules/@types/node/events.d.ts:317
