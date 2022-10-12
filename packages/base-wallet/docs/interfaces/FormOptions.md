# Interface: FormOptions<T\>

## Type parameters

| Name |
| :------ |
| `T` |

## Hierarchy

- [`BaseDialogOptions`](BaseDialogOptions.md)

  ↳ **`FormOptions`**

## Table of contents

### Properties

- [allowCancel](FormOptions.md#allowcancel)
- [descriptors](FormOptions.md#descriptors)
- [message](FormOptions.md#message)
- [order](FormOptions.md#order)
- [timeout](FormOptions.md#timeout)
- [title](FormOptions.md#title)

## Properties

### allowCancel

• `Optional` **allowCancel**: `boolean`

#### Inherited from

[BaseDialogOptions](BaseDialogOptions.md).[allowCancel](BaseDialogOptions.md#allowcancel)

#### Defined in

src/ts/app/dialog.ts:6

___

### descriptors

• **descriptors**: [`DescriptorsMap`](../API.md#descriptorsmap)<`T`\>

#### Defined in

src/ts/app/dialog.ts:48

___

### message

• `Optional` **message**: `string`

#### Inherited from

[BaseDialogOptions](BaseDialogOptions.md).[message](BaseDialogOptions.md#message)

#### Defined in

src/ts/app/dialog.ts:4

___

### order

• **order**: keyof `T`[]

#### Defined in

src/ts/app/dialog.ts:49

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
