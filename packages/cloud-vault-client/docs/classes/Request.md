# Class: Request

## Table of contents

### Constructors

- [constructor](Request.md#constructor)

### Properties

- [axios](Request.md#axios)
- [defaultCallOptions](Request.md#defaultcalloptions)
- [defaultUrl](Request.md#defaulturl)
- [ongoingRequests](Request.md#ongoingrequests)

### Methods

- [delete](Request.md#delete)
- [get](Request.md#get)
- [post](Request.md#post)
- [put](Request.md#put)
- [stop](Request.md#stop)
- [waitForOngoingRequestsToFinsh](Request.md#waitforongoingrequeststofinsh)

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

[cloud-vault-client/src/ts/request.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/579f9ce/packages/cloud-vault-client/src/ts/request.ts#L26)

## Properties

### axios

• **axios**: `AxiosInstance`

#### Defined in

[cloud-vault-client/src/ts/request.ts:18](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/579f9ce/packages/cloud-vault-client/src/ts/request.ts#L18)

___

### defaultCallOptions

• `Optional` **defaultCallOptions**: `CallOptions`<`unknown`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:19](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/579f9ce/packages/cloud-vault-client/src/ts/request.ts#L19)

___

### defaultUrl

• `Optional` **defaultUrl**: `string`

#### Defined in

[cloud-vault-client/src/ts/request.ts:20](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/579f9ce/packages/cloud-vault-client/src/ts/request.ts#L20)

___

### ongoingRequests

• **ongoingRequests**: `Object`

#### Index signature

▪ [url: `string`]: `Promise`<`AxiosResponse`\>[]

#### Defined in

[cloud-vault-client/src/ts/request.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/579f9ce/packages/cloud-vault-client/src/ts/request.ts#L22)

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

[cloud-vault-client/src/ts/request.ts:149](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/579f9ce/packages/cloud-vault-client/src/ts/request.ts#L149)

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

[cloud-vault-client/src/ts/request.ts:150](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/579f9ce/packages/cloud-vault-client/src/ts/request.ts#L150)

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

[cloud-vault-client/src/ts/request.ts:161](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/579f9ce/packages/cloud-vault-client/src/ts/request.ts#L161)

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

[cloud-vault-client/src/ts/request.ts:162](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/579f9ce/packages/cloud-vault-client/src/ts/request.ts#L162)

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

[cloud-vault-client/src/ts/request.ts:173](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/579f9ce/packages/cloud-vault-client/src/ts/request.ts#L173)

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

[cloud-vault-client/src/ts/request.ts:174](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/579f9ce/packages/cloud-vault-client/src/ts/request.ts#L174)

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

[cloud-vault-client/src/ts/request.ts:192](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/579f9ce/packages/cloud-vault-client/src/ts/request.ts#L192)

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

[cloud-vault-client/src/ts/request.ts:193](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/579f9ce/packages/cloud-vault-client/src/ts/request.ts#L193)

___

### stop

▸ **stop**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:72](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/579f9ce/packages/cloud-vault-client/src/ts/request.ts#L72)

___

### waitForOngoingRequestsToFinsh

▸ **waitForOngoingRequestsToFinsh**(`url?`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `url?` | `string` |

#### Returns

`Promise`<`void`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:58](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/579f9ce/packages/cloud-vault-client/src/ts/request.ts#L58)
