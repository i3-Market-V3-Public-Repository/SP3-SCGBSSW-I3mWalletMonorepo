# Interface: SelectOptions<T\>

## Type parameters

| Name |
| :------ |
| `T` |

## Hierarchy

- [`BaseDialogOptions`](BaseDialogOptions.md)

  ↳ **`SelectOptions`**

## Table of contents

### Properties

- [allowCancel](SelectOptions.md#allowcancel)
- [freeAnswer](SelectOptions.md#freeanswer)
- [getContext](SelectOptions.md#getcontext)
- [getText](SelectOptions.md#gettext)
- [message](SelectOptions.md#message)
- [showInput](SelectOptions.md#showinput)
- [timeout](SelectOptions.md#timeout)
- [title](SelectOptions.md#title)
- [values](SelectOptions.md#values)

## Properties

### allowCancel

• `Optional` **allowCancel**: `boolean`

#### Inherited from

[BaseDialogOptions](BaseDialogOptions.md).[allowCancel](BaseDialogOptions.md#allowcancel)

#### Defined in

[src/ts/app/dialog.ts:6](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/app/dialog.ts#L6)

___

### freeAnswer

• `Optional` **freeAnswer**: `boolean`

#### Defined in

[src/ts/app/dialog.ts:20](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/app/dialog.ts#L20)

___

### getContext

• `Optional` **getContext**: (`obj`: `T`) => [`DialogOptionContext`](../API.md#dialogoptioncontext)

#### Type declaration

▸ (`obj`): [`DialogOptionContext`](../API.md#dialogoptioncontext)

##### Parameters

| Name | Type |
| :------ | :------ |
| `obj` | `T` |

##### Returns

[`DialogOptionContext`](../API.md#dialogoptioncontext)

#### Defined in

[src/ts/app/dialog.ts:25](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/app/dialog.ts#L25)

___

### getText

• `Optional` **getText**: (`obj`: `T`) => `string`

#### Type declaration

▸ (`obj`): `string`

##### Parameters

| Name | Type |
| :------ | :------ |
| `obj` | `T` |

##### Returns

`string`

#### Defined in

[src/ts/app/dialog.ts:24](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/app/dialog.ts#L24)

___

### message

• `Optional` **message**: `string`

#### Inherited from

[BaseDialogOptions](BaseDialogOptions.md).[message](BaseDialogOptions.md#message)

#### Defined in

[src/ts/app/dialog.ts:4](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/app/dialog.ts#L4)

___

### showInput

• `Optional` **showInput**: `boolean`

#### Defined in

[src/ts/app/dialog.ts:21](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/app/dialog.ts#L21)

___

### timeout

• `Optional` **timeout**: `number`

#### Inherited from

[BaseDialogOptions](BaseDialogOptions.md).[timeout](BaseDialogOptions.md#timeout)

#### Defined in

[src/ts/app/dialog.ts:5](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/app/dialog.ts#L5)

___

### title

• `Optional` **title**: `string`

#### Inherited from

[BaseDialogOptions](BaseDialogOptions.md).[title](BaseDialogOptions.md#title)

#### Defined in

[src/ts/app/dialog.ts:3](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/app/dialog.ts#L3)

___

### values

• **values**: `T`[]

#### Defined in

[src/ts/app/dialog.ts:23](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/app/dialog.ts#L23)
