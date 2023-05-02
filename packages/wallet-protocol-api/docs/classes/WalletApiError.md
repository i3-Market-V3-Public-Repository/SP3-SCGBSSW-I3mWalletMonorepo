# Class: WalletApiError

## Hierarchy

- `Error`

  ↳ **`WalletApiError`**

## Table of contents

### Constructors

- [constructor](WalletApiError.md#constructor)

### Properties

- [body](WalletApiError.md#body)
- [code](WalletApiError.md#code)
- [message](WalletApiError.md#message)
- [name](WalletApiError.md#name)
- [stack](WalletApiError.md#stack)
- [prepareStackTrace](WalletApiError.md#preparestacktrace)
- [stackTraceLimit](WalletApiError.md#stacktracelimit)

### Methods

- [captureStackTrace](WalletApiError.md#capturestacktrace)

## Constructors

### constructor

• **new WalletApiError**(`message`, `code`, `body`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `message` | `string` |
| `code` | `number` |
| `body` | `any` |

#### Overrides

Error.constructor

#### Defined in

[src/ts/error.ts:3](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/645d0838/packages/wallet-protocol-api/src/ts/error.ts#L3)

## Properties

### body

• **body**: `any`

#### Defined in

[src/ts/error.ts:3](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/645d0838/packages/wallet-protocol-api/src/ts/error.ts#L3)

___

### code

• **code**: `number`

#### Defined in

[src/ts/error.ts:3](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/645d0838/packages/wallet-protocol-api/src/ts/error.ts#L3)

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
