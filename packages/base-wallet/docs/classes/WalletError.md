# Class: WalletError

## Hierarchy

- `Error`

  ↳ **`WalletError`**

## Table of contents

### Constructors

- [constructor](WalletError.md#constructor)

### Properties

- [code](WalletError.md#code)
- [message](WalletError.md#message)
- [name](WalletError.md#name)
- [stack](WalletError.md#stack)
- [status](WalletError.md#status)
- [prepareStackTrace](WalletError.md#preparestacktrace)
- [stackTraceLimit](WalletError.md#stacktracelimit)

### Methods

- [captureStackTrace](WalletError.md#capturestacktrace)

## Constructors

### constructor

• **new WalletError**(`message`, `httpData?`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `message` | `string` |
| `httpData?` | `HttpData` |

#### Overrides

Error.constructor

#### Defined in

[src/ts/errors.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/errors.ts#L11)

## Properties

### code

• **code**: `number`

#### Defined in

[src/ts/errors.ts:8](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/errors.ts#L8)

___

### message

• **message**: `string`

#### Inherited from

Error.message

#### Defined in

node_modules/typescript/lib/lib.es5.d.ts:1054

___

### name

• **name**: `string`

#### Inherited from

Error.name

#### Defined in

node_modules/typescript/lib/lib.es5.d.ts:1053

___

### stack

• `Optional` **stack**: `string`

#### Inherited from

Error.stack

#### Defined in

node_modules/typescript/lib/lib.es5.d.ts:1055

___

### status

• **status**: `number`

#### Defined in

[src/ts/errors.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/errors.ts#L9)

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

Error.prepareStackTrace

#### Defined in

node_modules/@types/node/globals.d.ts:11

___

### stackTraceLimit

▪ `Static` **stackTraceLimit**: `number`

#### Inherited from

Error.stackTraceLimit

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

Error.captureStackTrace

#### Defined in

node_modules/@types/node/globals.d.ts:4
