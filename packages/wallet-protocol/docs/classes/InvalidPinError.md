# Class: InvalidPinError

## Hierarchy

- [`WalletProtocolError`](WalletProtocolError.md)

  ↳ **`InvalidPinError`**

## Table of contents

### Constructors

- [constructor](InvalidPinError.md#constructor)

### Properties

- [message](InvalidPinError.md#message)
- [name](InvalidPinError.md#name)
- [stack](InvalidPinError.md#stack)
- [prepareStackTrace](InvalidPinError.md#preparestacktrace)
- [stackTraceLimit](InvalidPinError.md#stacktracelimit)

### Methods

- [captureStackTrace](InvalidPinError.md#capturestacktrace)

## Constructors

### constructor

• **new InvalidPinError**(`message?`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `message?` | `string` |

#### Inherited from

[WalletProtocolError](WalletProtocolError.md).[constructor](WalletProtocolError.md#constructor)

#### Defined in

node_modules/typescript/lib/lib.es5.d.ts:1059

## Properties

### message

• **message**: `string`

#### Inherited from

[WalletProtocolError](WalletProtocolError.md).[message](WalletProtocolError.md#message)

#### Defined in

node_modules/typescript/lib/lib.es5.d.ts:1054

___

### name

• **name**: `string`

#### Inherited from

[WalletProtocolError](WalletProtocolError.md).[name](WalletProtocolError.md#name)

#### Defined in

node_modules/typescript/lib/lib.es5.d.ts:1053

___

### stack

• `Optional` **stack**: `string`

#### Inherited from

[WalletProtocolError](WalletProtocolError.md).[stack](WalletProtocolError.md#stack)

#### Defined in

node_modules/typescript/lib/lib.es5.d.ts:1055

___

### prepareStackTrace

▪ `Static` `Optional` **prepareStackTrace**: (`err`: `Error`, `stackTraces`: `CallSite`[]) => `any`

#### Type declaration

▸ (`err`, `stackTraces`): `any`

Optional override for formatting stack traces

**`See`**

https://v8.dev/docs/stack-trace-api#customizing-stack-traces

##### Parameters

| Name | Type |
| :------ | :------ |
| `err` | `Error` |
| `stackTraces` | `CallSite`[] |

##### Returns

`any`

#### Inherited from

[WalletProtocolError](WalletProtocolError.md).[prepareStackTrace](WalletProtocolError.md#preparestacktrace)

#### Defined in

node_modules/@types/node/globals.d.ts:11

___

### stackTraceLimit

▪ `Static` **stackTraceLimit**: `number`

#### Inherited from

[WalletProtocolError](WalletProtocolError.md).[stackTraceLimit](WalletProtocolError.md#stacktracelimit)

#### Defined in

node_modules/@types/node/globals.d.ts:13

## Methods

### captureStackTrace

▸ `Static` **captureStackTrace**(`targetObject`, `constructorOpt?`): `void`

Create .stack property on a target object

#### Parameters

| Name | Type |
| :------ | :------ |
| `targetObject` | `object` |
| `constructorOpt?` | `Function` |

#### Returns

`void`

#### Inherited from

[WalletProtocolError](WalletProtocolError.md).[captureStackTrace](WalletProtocolError.md#capturestacktrace)

#### Defined in

node_modules/@types/node/globals.d.ts:4
