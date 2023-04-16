# Class: Request

## Table of contents

### Constructors

- [constructor](Request.md#constructor)

### Properties

- [axios](Request.md#axios)
- [defaultCallOptions](Request.md#defaultcalloptions)
- [defaultUrl](Request.md#defaulturl)
- [uploading](Request.md#uploading)

### Methods

- [delete](Request.md#delete)
- [get](Request.md#get)
- [post](Request.md#post)
- [put](Request.md#put)
- [stop](Request.md#stop)
- [waitForUploadsToFinsh](Request.md#waitforuploadstofinsh)

## Constructors

### constructor

• **new Request**(`opts?`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `opts?` | `Object` |
| `opts.defaultCallOptions?` | `CallOptions`<`unknown`\> |
| `opts.defaultUrl?` | `string` |
| `opts.retryOptions?` | [`RetryOptions`](../interfaces/RetryOptions.md) |

#### Defined in

[cloud-vault-client/src/ts/request.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/a3f9689/packages/cloud-vault-client/src/ts/request.ts#L26)

## Properties

### axios

• **axios**: `AxiosInstance`

#### Defined in

[cloud-vault-client/src/ts/request.ts:18](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/a3f9689/packages/cloud-vault-client/src/ts/request.ts#L18)

___

### defaultCallOptions

• `Optional` **defaultCallOptions**: `CallOptions`<`unknown`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:19](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/a3f9689/packages/cloud-vault-client/src/ts/request.ts#L19)

___

### defaultUrl

• `Optional` **defaultUrl**: `string`

#### Defined in

[cloud-vault-client/src/ts/request.ts:20](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/a3f9689/packages/cloud-vault-client/src/ts/request.ts#L20)

___

### uploading

• **uploading**: `Object`

#### Index signature

▪ [url: `string`]: `Promise`<`AxiosResponse`\>[]

#### Defined in

[cloud-vault-client/src/ts/request.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/a3f9689/packages/cloud-vault-client/src/ts/request.ts#L22)

## Methods

### delete

▸ **delete**<`T`\>(`url`, `options?`): `Promise`<`T`\>

#### Type parameters

| Name |
| :------ |
| `T` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `url` | `string` |
| `options?` | `CallOptions`<`T`\> |

#### Returns

`Promise`<`T`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:119](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/a3f9689/packages/cloud-vault-client/src/ts/request.ts#L119)

▸ **delete**<`T`\>(`options?`): `Promise`<`T`\>

#### Type parameters

| Name |
| :------ |
| `T` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `options?` | `CallOptions`<`T`\> |

#### Returns

`Promise`<`T`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:120](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/a3f9689/packages/cloud-vault-client/src/ts/request.ts#L120)

___

### get

▸ **get**<`T`\>(`url`, `options?`): `Promise`<`T`\>

#### Type parameters

| Name |
| :------ |
| `T` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `url` | `string` |
| `options?` | `CallOptions`<`T`\> |

#### Returns

`Promise`<`T`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:78](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/a3f9689/packages/cloud-vault-client/src/ts/request.ts#L78)

▸ **get**<`T`\>(`options?`): `Promise`<`T`\>

#### Type parameters

| Name |
| :------ |
| `T` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `options?` | `CallOptions`<`T`\> |

#### Returns

`Promise`<`T`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:79](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/a3f9689/packages/cloud-vault-client/src/ts/request.ts#L79)

___

### post

▸ **post**<`T`\>(`url`, `requestBody`, `options?`): `Promise`<`T`\>

#### Type parameters

| Name |
| :------ |
| `T` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `url` | `string` |
| `requestBody` | `any` |
| `options?` | `CallOptions`<`T`\> |

#### Returns

`Promise`<`T`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:218](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/a3f9689/packages/cloud-vault-client/src/ts/request.ts#L218)

▸ **post**<`T`\>(`requestBody`, `options?`): `Promise`<`T`\>

#### Type parameters

| Name |
| :------ |
| `T` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `any` |
| `options?` | `CallOptions`<`T`\> |

#### Returns

`Promise`<`T`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:219](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/a3f9689/packages/cloud-vault-client/src/ts/request.ts#L219)

___

### put

▸ **put**<`T`\>(`url`, `requestBody`, `options?`): `Promise`<`T`\>

#### Type parameters

| Name |
| :------ |
| `T` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `url` | `string` |
| `requestBody` | `any` |
| `options?` | `CallOptions`<`T`\> |

#### Returns

`Promise`<`T`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:237](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/a3f9689/packages/cloud-vault-client/src/ts/request.ts#L237)

▸ **put**<`T`\>(`requestBody`, `options?`): `Promise`<`T`\>

#### Type parameters

| Name |
| :------ |
| `T` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `any` |
| `options?` | `CallOptions`<`T`\> |

#### Returns

`Promise`<`T`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:238](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/a3f9689/packages/cloud-vault-client/src/ts/request.ts#L238)

___

### stop

▸ **stop**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:70](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/a3f9689/packages/cloud-vault-client/src/ts/request.ts#L70)

___

### waitForUploadsToFinsh

▸ **waitForUploadsToFinsh**(`url?`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `url?` | `string` |

#### Returns

`Promise`<`void`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:56](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/a3f9689/packages/cloud-vault-client/src/ts/request.ts#L56)
