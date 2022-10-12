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
- [getContext](SelectOptions.md#getcontext)
- [getText](SelectOptions.md#gettext)
- [message](SelectOptions.md#message)
- [timeout](SelectOptions.md#timeout)
- [title](SelectOptions.md#title)
- [values](SelectOptions.md#values)

## Properties

### allowCancel

• `Optional` **allowCancel**: `boolean`

#### Inherited from

[BaseDialogOptions](BaseDialogOptions.md).[allowCancel](BaseDialogOptions.md#allowcancel)

#### Defined in

src/ts/app/dialog.ts:6

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

src/ts/app/dialog.ts:22

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

src/ts/app/dialog.ts:21

___

### message

• `Optional` **message**: `string`

#### Inherited from

[BaseDialogOptions](BaseDialogOptions.md).[message](BaseDialogOptions.md#message)

#### Defined in

src/ts/app/dialog.ts:4

___

### timeout

• `Optional` **timeout**: `number`

#### Inherited from

[BaseDialogOptions](BaseDialogOptions.md).[timeout](BaseDialogOptions.md#timeout)

#### Defined in

src/ts/app/dialog.ts:5

___

### title

• `Optional` **title**: `string`

#### Inherited from

[BaseDialogOptions](BaseDialogOptions.md).[title](BaseDialogOptions.md#title)

#### Defined in

src/ts/app/dialog.ts:3

___

### values

• **values**: `T`[]

#### Defined in

src/ts/app/dialog.ts:20
