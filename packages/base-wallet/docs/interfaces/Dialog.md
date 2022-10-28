# Interface: Dialog

## Implemented by

- [`NullDialog`](../classes/NullDialog.md)
- [`TestDialog`](../classes/TestDialog.md)

## Table of contents

### Properties

- [authenticate](Dialog.md#authenticate)
- [confirmation](Dialog.md#confirmation)
- [form](Dialog.md#form)
- [select](Dialog.md#select)
- [text](Dialog.md#text)

## Properties

### authenticate

• **authenticate**: () => [`DialogResponse`](../API.md#dialogresponse)<`boolean`\>

#### Type declaration

▸ (): [`DialogResponse`](../API.md#dialogresponse)<`boolean`\>

##### Returns

[`DialogResponse`](../API.md#dialogresponse)<`boolean`\>

#### Defined in

[base-wallet/src/ts/app/dialog.ts:57](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/33162c9/packages/base-wallet/src/ts/app/dialog.ts#L57)

___

### confirmation

• **confirmation**: (`options`: [`ConfirmationOptions`](ConfirmationOptions.md)) => [`DialogResponse`](../API.md#dialogresponse)<`boolean`\>

#### Type declaration

▸ (`options`): [`DialogResponse`](../API.md#dialogresponse)<`boolean`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `options` | [`ConfirmationOptions`](ConfirmationOptions.md) |

##### Returns

[`DialogResponse`](../API.md#dialogresponse)<`boolean`\>

#### Defined in

[base-wallet/src/ts/app/dialog.ts:56](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/33162c9/packages/base-wallet/src/ts/app/dialog.ts#L56)

___

### form

• **form**: <T\>(`options`: [`FormOptions`](FormOptions.md)<`T`\>) => [`DialogResponse`](../API.md#dialogresponse)<`T`\>

#### Type declaration

▸ <`T`\>(`options`): [`DialogResponse`](../API.md#dialogresponse)<`T`\>

##### Type parameters

| Name |
| :------ |
| `T` |

##### Parameters

| Name | Type |
| :------ | :------ |
| `options` | [`FormOptions`](FormOptions.md)<`T`\> |

##### Returns

[`DialogResponse`](../API.md#dialogresponse)<`T`\>

#### Defined in

[base-wallet/src/ts/app/dialog.ts:59](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/33162c9/packages/base-wallet/src/ts/app/dialog.ts#L59)

___

### select

• **select**: <T\>(`options`: [`SelectOptions`](SelectOptions.md)<`T`\>) => [`DialogResponse`](../API.md#dialogresponse)<`T`\>

#### Type declaration

▸ <`T`\>(`options`): [`DialogResponse`](../API.md#dialogresponse)<`T`\>

##### Type parameters

| Name |
| :------ |
| `T` |

##### Parameters

| Name | Type |
| :------ | :------ |
| `options` | [`SelectOptions`](SelectOptions.md)<`T`\> |

##### Returns

[`DialogResponse`](../API.md#dialogresponse)<`T`\>

#### Defined in

[base-wallet/src/ts/app/dialog.ts:58](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/33162c9/packages/base-wallet/src/ts/app/dialog.ts#L58)

___

### text

• **text**: (`options`: [`TextOptions`](TextOptions.md)) => [`DialogResponse`](../API.md#dialogresponse)<`string`\>

#### Type declaration

▸ (`options`): [`DialogResponse`](../API.md#dialogresponse)<`string`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `options` | [`TextOptions`](TextOptions.md) |

##### Returns

[`DialogResponse`](../API.md#dialogresponse)<`string`\>

#### Defined in

[base-wallet/src/ts/app/dialog.ts:55](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/33162c9/packages/base-wallet/src/ts/app/dialog.ts#L55)
