# Interface: VaultConnError

## Table of contents

### Properties

- [request](VaultConnError.md#request)
- [response](VaultConnError.md#response)

## Properties

### request

• **request**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `data?` | `any` |
| `headers?` | { `[header: string]`: `string`;  } |
| `method?` | `string` |
| `url?` | `string` |

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2705a55/packages/cloud-vault-client/src/ts/vault-client.ts#L22)

___

### response

• `Optional` **response**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `data?` | `any` |
| `headers?` | { `[header: string]`: `string`;  } |
| `status?` | `number` |

#### Defined in

[cloud-vault-client/src/ts/vault-client.ts:28](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/2705a55/packages/cloud-vault-client/src/ts/vault-client.ts#L28)
