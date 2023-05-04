# @i3m/wallet-protocol-utils - v2.6.0

## Table of contents

### Classes

- [LocalSessionManager](classes/LocalSessionManager.md)
- [SessionManager](classes/SessionManager.md)

### Interfaces

- [PinConsoleDialogOptions](interfaces/PinConsoleDialogOptions.md)
- [PinDialogOptions](interfaces/PinDialogOptions.md)
- [PinHtmlFormDialogOptions](interfaces/PinHtmlFormDialogOptions.md)
- [SessionFileStorageOptions](interfaces/SessionFileStorageOptions.md)
- [SessionLocalStorageOptions](interfaces/SessionLocalStorageOptions.md)
- [SessionManagerOptions](interfaces/SessionManagerOptions.md)
- [SessionManagerOpts](interfaces/SessionManagerOpts.md)
- [SessionStorage](interfaces/SessionStorage.md)
- [SessionStorageOptions](interfaces/SessionStorageOptions.md)

### Type Aliases

- [CanBePromise](API.md#canbepromise)

### Functions

- [openModal](API.md#openmodal)
- [pinDialog](API.md#pindialog)

## Type Aliases

### CanBePromise

Ƭ **CanBePromise**<`T`\>: `Promise`<`T`\> \| `T`

#### Type parameters

| Name |
| :------ |
| `T` |

#### Defined in

[wallet-protocol-utils/src/ts/types.ts:3](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fe110225/packages/wallet-protocol-utils/src/ts/types.ts#L3)

## Functions

### openModal

▸ **openModal**(`opts?`): `Promise`<`string`\>

A PIN input dialog. In node is a promise that resolves to a PIN that is requested through the console to the end user. In browsers it shows an HTML formulary where to write the PIN, and returns a promise that resolves to that PIN when a user fills it and submits it.

**`Deprecated`**

Use [pinDialog](API.md#pindialog) instead.

#### Parameters

| Name | Type |
| :------ | :------ |
| `opts?` | [`PinDialogOptions`](interfaces/PinDialogOptions.md) |

#### Returns

`Promise`<`string`\>

a promise that resolves to the PIN

#### Defined in

[wallet-protocol-utils/src/ts/pin-dialog.ts:8](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fe110225/packages/wallet-protocol-utils/src/ts/pin-dialog.ts#L8)

___

### pinDialog

▸ **pinDialog**(`opts?`): `Promise`<`string`\>

A PIN input dialog. In node is a promise that resolves to a PIN that is requested through the console to the end user. In browsers it shows an HTML formulary where to write the PIN, and returns a promise that resolves to that PIN when a user fills it and submits it.

#### Parameters

| Name | Type |
| :------ | :------ |
| `opts?` | [`PinDialogOptions`](interfaces/PinDialogOptions.md) |

#### Returns

`Promise`<`string`\>

a promise that resolves to the PIN

#### Defined in

[wallet-protocol-utils/src/ts/pin-dialog.ts:8](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/fe110225/packages/wallet-protocol-utils/src/ts/pin-dialog.ts#L8)
