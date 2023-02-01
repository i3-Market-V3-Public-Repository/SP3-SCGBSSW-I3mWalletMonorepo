# Class: KeyManager

## Table of contents

### Constructors

- [constructor](KeyManager.md#constructor)

### Properties

- [derivationOptions](KeyManager.md#derivationoptions)
- [initialized](KeyManager.md#initialized)

### Methods

- [getAuthKey](KeyManager.md#getauthkey)
- [getEncKey](KeyManager.md#getenckey)

## Constructors

### constructor

• **new KeyManager**(`password`, `opts`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `password` | `BinaryLike` |
| `opts` | [`DerivationOptions`](../interfaces/DerivationOptions.md) |

#### Defined in

src/ts/key-manager.ts:29

## Properties

### derivationOptions

• **derivationOptions**: [`DerivationOptions`](../interfaces/DerivationOptions.md)

#### Defined in

src/ts/key-manager.ts:26

___

### initialized

• **initialized**: `Promise`<`void`\>

#### Defined in

src/ts/key-manager.ts:27

## Methods

### getAuthKey

▸ **getAuthKey**(): `Promise`<`string`\>

#### Returns

`Promise`<`string`\>

#### Defined in

src/ts/key-manager.ts:46

___

### getEncKey

▸ **getEncKey**(): `Promise`<`KeyObject`\>

#### Returns

`Promise`<`KeyObject`\>

#### Defined in

src/ts/key-manager.ts:51
