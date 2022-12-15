# @i3m/wallet-protocol-utils - v2.3.1

## Table of contents

### Classes

- [LocalSessionManager](classes/LocalSessionManager.md)
- [SessionManager](classes/SessionManager.md)

### Functions

- [openModal](API.md#openmodal)
- [pinDialog](API.md#pindialog)

## Functions

### openModal

▸ **openModal**(`opts?`): `Promise`<`string`\>

A PIN input dialog. In node is a promise that resolves to a PIN that is requested through the console to the end user. In browsers it shows an HTML formulary where to write the PIN, and returns a promise that resolves to that PIN when a user fills it and submits it.

**`Deprecated`**

Use [pinDialog](API.md#pindialog) instead.

#### Parameters

| Name | Type |
| :------ | :------ |
| `opts?` | `PinDialogOptions` |

#### Returns

`Promise`<`string`\>

a promise that resolves to the PIN

#### Defined in

[wallet-protocol-utils/src/ts/pin-dialog.ts:8](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9f0c02f/packages/wallet-protocol-utils/src/ts/pin-dialog.ts#L8)

___

### pinDialog

▸ **pinDialog**(`opts?`): `Promise`<`string`\>

A PIN input dialog. In node is a promise that resolves to a PIN that is requested through the console to the end user. In browsers it shows an HTML formulary where to write the PIN, and returns a promise that resolves to that PIN when a user fills it and submits it.

#### Parameters

| Name | Type |
| :------ | :------ |
| `opts?` | `PinDialogOptions` |

#### Returns

`Promise`<`string`\>

a promise that resolves to the PIN

#### Defined in

[wallet-protocol-utils/src/ts/pin-dialog.ts:8](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9f0c02f/packages/wallet-protocol-utils/src/ts/pin-dialog.ts#L8)
