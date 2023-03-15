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
| `opts.defaultCallOptions?` | `CallOptions` |
| `opts.defaultUrl?` | `string` |
| `opts.retryOptions?` | [`RetryOptions`](../interfaces/RetryOptions.md) |

#### Defined in

[cloud-vault-client/src/ts/request.ts:25](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/request.ts#L25)

## Properties

### axios

• **axios**: `AxiosInstance`

#### Defined in

[cloud-vault-client/src/ts/request.ts:17](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/request.ts#L17)

___

### defaultCallOptions

• `Optional` **defaultCallOptions**: `CallOptions`

#### Defined in

[cloud-vault-client/src/ts/request.ts:18](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/request.ts#L18)

___

### defaultUrl

• `Optional` **defaultUrl**: `string`

#### Defined in

[cloud-vault-client/src/ts/request.ts:19](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/request.ts#L19)

___

### uploading

• **uploading**: `Object`

#### Index signature

▪ [url: `string`]: `Promise`<`AxiosResponse`\>[]

#### Defined in

[cloud-vault-client/src/ts/request.ts:21](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/request.ts#L21)

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
| `options?` | `CallOptions` |

#### Returns

`Promise`<`T`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:118](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/request.ts#L118)

▸ **delete**<`T`\>(`options?`): `Promise`<`T`\>

#### Type parameters

| Name |
| :------ |
| `T` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `options?` | `CallOptions` |

#### Returns

`Promise`<`T`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:119](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/request.ts#L119)

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
| `options?` | `CallOptions` |

#### Returns

`Promise`<`T`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:77](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/request.ts#L77)

▸ **get**<`T`\>(`options?`): `Promise`<`T`\>

#### Type parameters

| Name |
| :------ |
| `T` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `options?` | `CallOptions` |

#### Returns

`Promise`<`T`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:78](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/request.ts#L78)

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
| `options?` | `CallOptions` |

#### Returns

`Promise`<`T`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:212](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/request.ts#L212)

▸ **post**<`T`\>(`requestBody`, `options?`): `Promise`<`T`\>

#### Type parameters

| Name |
| :------ |
| `T` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `any` |
| `options?` | `CallOptions` |

#### Returns

`Promise`<`T`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:213](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/request.ts#L213)

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
| `options?` | `CallOptions` |

#### Returns

`Promise`<`T`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:231](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/request.ts#L231)

▸ **put**<`T`\>(`requestBody`, `options?`): `Promise`<`T`\>

#### Type parameters

| Name |
| :------ |
| `T` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `any` |
| `options?` | `CallOptions` |

#### Returns

`Promise`<`T`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:232](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/request.ts#L232)

___

### stop

▸ **stop**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:69](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/request.ts#L69)

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

[cloud-vault-client/src/ts/request.ts:55](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f802a57/packages/cloud-vault-client/src/ts/request.ts#L55)
