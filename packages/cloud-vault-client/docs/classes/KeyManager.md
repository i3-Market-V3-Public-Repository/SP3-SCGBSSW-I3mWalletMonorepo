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

[src/ts/key-manager.ts:29](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/cloud-vault-client/src/ts/key-manager.ts#L29)

## Properties

### derivationOptions

• **derivationOptions**: [`DerivationOptions`](../interfaces/DerivationOptions.md)

#### Defined in

[src/ts/key-manager.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/cloud-vault-client/src/ts/key-manager.ts#L26)

___

### initialized

• **initialized**: `Promise`<`void`\>

#### Defined in

[src/ts/key-manager.ts:27](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/cloud-vault-client/src/ts/key-manager.ts#L27)

## Methods

### getAuthKey

▸ **getAuthKey**(): `Promise`<`string`\>

#### Returns

`Promise`<`string`\>

#### Defined in

[src/ts/key-manager.ts:46](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/cloud-vault-client/src/ts/key-manager.ts#L46)

___

### getEncKey

▸ **getEncKey**(): `Promise`<`KeyObject`\>

#### Returns

`Promise`<`KeyObject`\>

#### Defined in

[src/ts/key-manager.ts:51](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/53c581f/packages/cloud-vault-client/src/ts/key-manager.ts#L51)
