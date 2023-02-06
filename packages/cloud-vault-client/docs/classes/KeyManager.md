# Class: KeyManager

## Table of contents

### Constructors

- [constructor](KeyManager.md#constructor)

### Properties

- [derivationOptions](KeyManager.md#derivationoptions)
- [initialized](KeyManager.md#initialized)
- [username](KeyManager.md#username)

### Methods

- [getAuthKey](KeyManager.md#getauthkey)
- [getEncKey](KeyManager.md#getenckey)

## Constructors

### constructor

• **new KeyManager**(`username`, `password`, `opts`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `username` | `string` |
| `password` | `string` |
| `opts` | `Object` |
| `opts.auth` | `KeyDerivationOptions` |
| `opts.enc` | `KeyDerivationOptions` |
| `opts.master` | `KeyDerivationOptions` |

#### Defined in

[cloud-vault-client/src/ts/key-manager.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/ec1c8b6/packages/cloud-vault-client/src/ts/key-manager.ts#L22)

## Properties

### derivationOptions

• **derivationOptions**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `auth` | `KeyDerivationOptions` |
| `enc` | `KeyDerivationOptions` |
| `master` | `KeyDerivationOptions` |

#### Defined in

[cloud-vault-client/src/ts/key-manager.ts:19](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/ec1c8b6/packages/cloud-vault-client/src/ts/key-manager.ts#L19)

___

### initialized

• **initialized**: `Promise`<`void`\>

#### Defined in

[cloud-vault-client/src/ts/key-manager.ts:20](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/ec1c8b6/packages/cloud-vault-client/src/ts/key-manager.ts#L20)

___

### username

• **username**: `string`

#### Defined in

[cloud-vault-client/src/ts/key-manager.ts:18](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/ec1c8b6/packages/cloud-vault-client/src/ts/key-manager.ts#L18)

## Methods

### getAuthKey

▸ **getAuthKey**(): `Promise`<`string`\>

#### Returns

`Promise`<`string`\>

#### Defined in

[cloud-vault-client/src/ts/key-manager.ts:45](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/ec1c8b6/packages/cloud-vault-client/src/ts/key-manager.ts#L45)

___

### getEncKey

▸ **getEncKey**(): `Promise`<`KeyObject`\>

#### Returns

`Promise`<`KeyObject`\>

#### Defined in

[cloud-vault-client/src/ts/key-manager.ts:50](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/ec1c8b6/packages/cloud-vault-client/src/ts/key-manager.ts#L50)
