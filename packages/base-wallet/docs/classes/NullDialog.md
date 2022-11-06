# Class: NullDialog

## Implements

- [`Dialog`](../interfaces/Dialog.md)

## Table of contents

### Constructors

- [constructor](NullDialog.md#constructor)

### Accessors

- [values](NullDialog.md#values)

### Methods

- [authenticate](NullDialog.md#authenticate)
- [confirmation](NullDialog.md#confirmation)
- [form](NullDialog.md#form)
- [select](NullDialog.md#select)
- [setValues](NullDialog.md#setvalues)
- [text](NullDialog.md#text)

## Constructors

### constructor

• **new NullDialog**()

## Accessors

### values

• `get` **values**(): `Values`

#### Returns

`Values`

#### Defined in

[base-wallet/src/ts/impl/dialogs/null-dialog.ts:33](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9fbbadb/packages/base-wallet/src/ts/impl/dialogs/null-dialog.ts#L33)

## Methods

### authenticate

▸ **authenticate**(): [`DialogResponse`](../API.md#dialogresponse)<`boolean`\>

#### Returns

[`DialogResponse`](../API.md#dialogresponse)<`boolean`\>

#### Implementation of

Dialog.authenticate

#### Defined in

[base-wallet/src/ts/impl/dialogs/null-dialog.ts:60](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9fbbadb/packages/base-wallet/src/ts/impl/dialogs/null-dialog.ts#L60)

___

### confirmation

▸ **confirmation**(`options`): [`DialogResponse`](../API.md#dialogresponse)<`boolean`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `options` | [`ConfirmationOptions`](../interfaces/ConfirmationOptions.md) |

#### Returns

[`DialogResponse`](../API.md#dialogresponse)<`boolean`\>

#### Implementation of

Dialog.confirmation

#### Defined in

[base-wallet/src/ts/impl/dialogs/null-dialog.ts:49](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9fbbadb/packages/base-wallet/src/ts/impl/dialogs/null-dialog.ts#L49)

___

### form

▸ **form**<`T`\>(`options`): [`DialogResponse`](../API.md#dialogresponse)<`T`\>

#### Type parameters

| Name |
| :------ |
| `T` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `options` | [`FormOptions`](../interfaces/FormOptions.md)<`T`\> |

#### Returns

[`DialogResponse`](../API.md#dialogresponse)<`T`\>

#### Implementation of

Dialog.form

#### Defined in

[base-wallet/src/ts/impl/dialogs/null-dialog.ts:64](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9fbbadb/packages/base-wallet/src/ts/impl/dialogs/null-dialog.ts#L64)

___

### select

▸ **select**<`T`\>(`options`): [`DialogResponse`](../API.md#dialogresponse)<`T`\>

#### Type parameters

| Name |
| :------ |
| `T` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `options` | [`SelectOptions`](../interfaces/SelectOptions.md)<`T`\> |

#### Returns

[`DialogResponse`](../API.md#dialogresponse)<`T`\>

#### Implementation of

Dialog.select

#### Defined in

[base-wallet/src/ts/impl/dialogs/null-dialog.ts:54](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9fbbadb/packages/base-wallet/src/ts/impl/dialogs/null-dialog.ts#L54)

___

### setValues

▸ **setValues**(`values`, `cb`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `values` | `Partial`<`Values`\> |
| `cb` | () => `Promise`<`void`\> |

#### Returns

`Promise`<`void`\>

#### Defined in

[base-wallet/src/ts/impl/dialogs/null-dialog.ts:37](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9fbbadb/packages/base-wallet/src/ts/impl/dialogs/null-dialog.ts#L37)

___

### text

▸ **text**(`options`): [`DialogResponse`](../API.md#dialogresponse)<`string`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `options` | [`TextOptions`](../interfaces/TextOptions.md) |

#### Returns

[`DialogResponse`](../API.md#dialogresponse)<`string`\>

#### Implementation of

Dialog.text

#### Defined in

[base-wallet/src/ts/impl/dialogs/null-dialog.ts:44](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9fbbadb/packages/base-wallet/src/ts/impl/dialogs/null-dialog.ts#L44)
