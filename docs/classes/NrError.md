# Class: NrError

## Hierarchy

- `Error`

  ↳ **`NrError`**

## Table of contents

### Constructors

- [constructor](NrError.md#constructor)

### Properties

- [message](NrError.md#message)
- [name](NrError.md#name)
- [nrErrors](NrError.md#nrerrors)
- [stack](NrError.md#stack)
- [prepareStackTrace](NrError.md#preparestacktrace)
- [stackTraceLimit](NrError.md#stacktracelimit)

### Methods

- [add](NrError.md#add)
- [captureStackTrace](NrError.md#capturestacktrace)

## Constructors

### constructor

• **new NrError**(`error`, `nrErrors`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `error` | `any` |
| `nrErrors` | [`NrErrorName`](../API.md#nrerrorname)[] |

#### Overrides

Error.constructor

#### Defined in

[src/ts/errors/NrError.ts:6](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/5928320/src/ts/errors/NrError.ts#L6)

## Properties

### message

• **message**: `string`

#### Inherited from

Error.message

#### Defined in

node_modules/typescript/lib/lib.es5.d.ts:1041

___

### name

• **name**: `string`

#### Inherited from

Error.name

#### Defined in

node_modules/typescript/lib/lib.es5.d.ts:1040

___

### nrErrors

• **nrErrors**: [`NrErrorName`](../API.md#nrerrorname)[]

#### Defined in

[src/ts/errors/NrError.ts:4](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/5928320/src/ts/errors/NrError.ts#L4)

___

### stack

• `Optional` **stack**: `string`

#### Inherited from

Error.stack

#### Defined in

node_modules/typescript/lib/lib.es5.d.ts:1042

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

node_modules/@types/node/ts4.8/globals.d.ts:11

___

### stackTraceLimit

▪ `Static` **stackTraceLimit**: `number`

#### Inherited from

Error.stackTraceLimit

#### Defined in

node_modules/@types/node/ts4.8/globals.d.ts:13

## Methods

### add

▸ **add**(...`nrErrors`): `void`

#### Parameters

| Name | Type |
| :------ | :------ |
| `...nrErrors` | [`NrErrorName`](../API.md#nrerrorname)[] |

#### Returns

`void`

#### Defined in

[src/ts/errors/NrError.ts:16](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/5928320/src/ts/errors/NrError.ts#L16)

___

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

node_modules/@types/node/ts4.8/globals.d.ts:4
