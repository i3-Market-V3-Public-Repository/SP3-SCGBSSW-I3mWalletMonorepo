# Interface: CodeGenerator

## Table of contents

### Properties

- [generate](CodeGenerator.md#generate)
- [getMasterKey](CodeGenerator.md#getmasterkey)

## Properties

### generate

• **generate**: (`masterKey`: [`MasterKey`](../classes/MasterKey.md)) => `Promise`<`Uint8Array`\>

#### Type declaration

▸ (`masterKey`): `Promise`<`Uint8Array`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `masterKey` | [`MasterKey`](../classes/MasterKey.md) |

##### Returns

`Promise`<`Uint8Array`\>

#### Defined in

[src/ts/protocol/code-generator.ts:5](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/wallet-protocol/src/ts/protocol/code-generator.ts#L5)

___

### getMasterKey

• **getMasterKey**: (`code`: `Uint8Array`) => `Promise`<[`MasterKey`](../classes/MasterKey.md)\>

#### Type declaration

▸ (`code`): `Promise`<[`MasterKey`](../classes/MasterKey.md)\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `code` | `Uint8Array` |

##### Returns

`Promise`<[`MasterKey`](../classes/MasterKey.md)\>

#### Defined in

[src/ts/protocol/code-generator.ts:6](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/wallet-protocol/src/ts/protocol/code-generator.ts#L6)
