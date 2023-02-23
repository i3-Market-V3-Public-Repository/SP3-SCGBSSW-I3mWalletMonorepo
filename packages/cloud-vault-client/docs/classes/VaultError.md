# Class: VaultError<T\>

## Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends [`VaultErrorName`](../API.md#vaulterrorname) = [`VaultErrorName`](../API.md#vaulterrorname) |

## Hierarchy

- `Error`

  ↳ **`VaultError`**

## Table of contents

### Constructors

- [constructor](VaultError.md#constructor)

### Properties

- [cause](VaultError.md#cause)
- [data](VaultError.md#data)
- [message](VaultError.md#message)
- [name](VaultError.md#name)
- [stack](VaultError.md#stack)
- [prepareStackTrace](VaultError.md#preparestacktrace)
- [stackTraceLimit](VaultError.md#stacktracelimit)

### Methods

- [captureStackTrace](VaultError.md#capturestacktrace)
- [from](VaultError.md#from)

## Constructors

### constructor

• **new VaultError**<`T`\>(`message`, `data`, `options?`)

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends keyof [`VaultErrorData`](../API.md#vaulterrordata) = keyof [`VaultErrorData`](../API.md#vaulterrordata) |

#### Parameters

| Name | Type |
| :------ | :------ |
| `message` | `T` |
| `data` | [`DataForError`](../API.md#dataforerror)<`T`\> |
| `options?` | `ErrorOptions` |

#### Overrides

Error.constructor

#### Defined in

[cloud-vault-client/src/ts/error.ts:43](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2ba611f/packages/cloud-vault-client/src/ts/error.ts#L43)

## Properties

### cause

• `Optional` **cause**: `unknown`

#### Inherited from

Error.cause

#### Defined in

cloud-vault-client/node_modules/typescript/lib/lib.es2022.error.d.ts:26

___

### data

• **data**: `any`

#### Defined in

[cloud-vault-client/src/ts/error.ts:40](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2ba611f/packages/cloud-vault-client/src/ts/error.ts#L40)

___

### message

• **message**: `T`

#### Overrides

Error.message

#### Defined in

[cloud-vault-client/src/ts/error.ts:41](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2ba611f/packages/cloud-vault-client/src/ts/error.ts#L41)

___

### name

• **name**: `string`

#### Inherited from

Error.name

#### Defined in

cloud-vault-client/node_modules/typescript/lib/lib.es5.d.ts:1053

___

### stack

• `Optional` **stack**: `string`

#### Inherited from

Error.stack

#### Defined in

cloud-vault-client/node_modules/typescript/lib/lib.es5.d.ts:1055

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

cloud-vault-client/node_modules/@types/node/globals.d.ts:11

___

### stackTraceLimit

▪ `Static` **stackTraceLimit**: `number`

#### Inherited from

Error.stackTraceLimit

#### Defined in

cloud-vault-client/node_modules/@types/node/globals.d.ts:13

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

cloud-vault-client/node_modules/@types/node/globals.d.ts:4

___

### from

▸ `Static` **from**(`error`): [`VaultError`](VaultError.md)<keyof [`VaultErrorData`](../API.md#vaulterrordata)\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `error` | `unknown` |

#### Returns

[`VaultError`](VaultError.md)<keyof [`VaultErrorData`](../API.md#vaulterrordata)\>

#### Defined in

[cloud-vault-client/src/ts/error.ts:51](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2ba611f/packages/cloud-vault-client/src/ts/error.ts#L51)
