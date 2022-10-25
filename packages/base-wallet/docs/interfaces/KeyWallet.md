# Interface: KeyWallet<T\>

## Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends [`TypedArray`](../API.md#typedarray) = `Uint8Array` |

## Table of contents

### Properties

- [createAccountKeyPair](KeyWallet.md#createaccountkeypair)
- [delete](KeyWallet.md#delete)
- [getPublicKey](KeyWallet.md#getpublickey)
- [signDigest](KeyWallet.md#signdigest)
- [wipe](KeyWallet.md#wipe)

## Properties

### createAccountKeyPair

• **createAccountKeyPair**: () => `Promise`<`string`\>

#### Type declaration

▸ (): `Promise`<`string`\>

Creates a key pair

##### Returns

`Promise`<`string`\>

a promise that resolves to the key id.

#### Defined in

[src/ts/keywallet/key-wallet.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9dba545/packages/base-wallet/src/ts/keywallet/key-wallet.ts#L9)

___

### delete

• **delete**: (`id`: `string`) => `Promise`<`boolean`\>

#### Type declaration

▸ (`id`): `Promise`<`boolean`\>

**`Throws`**

Error - Any error

##### Parameters

| Name | Type |
| :------ | :------ |
| `id` | `string` |

##### Returns

`Promise`<`boolean`\>

#### Defined in

[src/ts/keywallet/key-wallet.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9dba545/packages/base-wallet/src/ts/keywallet/key-wallet.ts#L26)

___

### getPublicKey

• **getPublicKey**: (`id`: `string`) => `Promise`<`Uint8Array`\>

#### Type declaration

▸ (`id`): `Promise`<`Uint8Array`\>

Gets a public key

##### Parameters

| Name | Type |
| :------ | :------ |
| `id` | `string` |

##### Returns

`Promise`<`Uint8Array`\>

a promise that resolves to a public key

#### Defined in

[src/ts/keywallet/key-wallet.ts:16](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9dba545/packages/base-wallet/src/ts/keywallet/key-wallet.ts#L16)

___

### signDigest

• **signDigest**: (`id`: `string`, `message`: `T`) => `Promise`<`T`\>

#### Type declaration

▸ (`id`, `message`): `Promise`<`T`\>

Signs input message and returns DER encoded typed array

##### Parameters

| Name | Type |
| :------ | :------ |
| `id` | `string` |
| `message` | `T` |

##### Returns

`Promise`<`T`\>

#### Defined in

[src/ts/keywallet/key-wallet.ts:21](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9dba545/packages/base-wallet/src/ts/keywallet/key-wallet.ts#L21)

___

### wipe

• **wipe**: () => `Promise`<`void`\>

#### Type declaration

▸ (): `Promise`<`void`\>

**`Throws`**

Error - Any error

##### Returns

`Promise`<`void`\>

#### Defined in

[src/ts/keywallet/key-wallet.ts:31](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/9dba545/packages/base-wallet/src/ts/keywallet/key-wallet.ts#L31)
