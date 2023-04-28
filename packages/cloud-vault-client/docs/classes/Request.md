# Class: Request

## Table of contents

### Constructors

- [constructor](Request.md#constructor)

### Properties

- [\_defaultCallOptions](Request.md#_defaultcalloptions)
- [\_defaultUrl](Request.md#_defaulturl)
- [ongoingRequests](Request.md#ongoingrequests)

### Accessors

- [defaultCallOptions](Request.md#defaultcalloptions)
- [defaultUrl](Request.md#defaulturl)

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

[cloud-vault-client/src/ts/request.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c392ccb/packages/cloud-vault-client/src/ts/request.ts#L26)

## Properties

### \_defaultCallOptions

• **\_defaultCallOptions**: `CallOptions`<`unknown`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:19](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c392ccb/packages/cloud-vault-client/src/ts/request.ts#L19)

___

### \_defaultUrl

• `Optional` **\_defaultUrl**: `string`

#### Defined in

[cloud-vault-client/src/ts/request.ts:20](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c392ccb/packages/cloud-vault-client/src/ts/request.ts#L20)

___

### ongoingRequests

• **ongoingRequests**: `Object`

#### Index signature

▪ [url: `string`]: `Promise`<`AxiosResponse`\>[]

#### Defined in

[cloud-vault-client/src/ts/request.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c392ccb/packages/cloud-vault-client/src/ts/request.ts#L22)

## Accessors

### defaultCallOptions

• `get` **defaultCallOptions**(): `CallOptions`<`unknown`\>

#### Returns

`CallOptions`<`unknown`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:46](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c392ccb/packages/cloud-vault-client/src/ts/request.ts#L46)

• `set` **defaultCallOptions**(`opts`): `void`

#### Parameters

| Name | Type |
| :------ | :------ |
| `opts` | `CallOptions`<`unknown`\> |

#### Returns

`void`

#### Defined in

[cloud-vault-client/src/ts/request.ts:50](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c392ccb/packages/cloud-vault-client/src/ts/request.ts#L50)

___

### defaultUrl

• `get` **defaultUrl**(): `undefined` \| `string`

#### Returns

`undefined` \| `string`

#### Defined in

[cloud-vault-client/src/ts/request.ts:38](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c392ccb/packages/cloud-vault-client/src/ts/request.ts#L38)

• `set` **defaultUrl**(`url`): `void`

#### Parameters

| Name | Type |
| :------ | :------ |
| `url` | `undefined` \| `string` |

#### Returns

`void`

#### Defined in

[cloud-vault-client/src/ts/request.ts:42](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c392ccb/packages/cloud-vault-client/src/ts/request.ts#L42)

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

[cloud-vault-client/src/ts/request.ts:160](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c392ccb/packages/cloud-vault-client/src/ts/request.ts#L160)

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

[cloud-vault-client/src/ts/request.ts:161](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c392ccb/packages/cloud-vault-client/src/ts/request.ts#L161)

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

[cloud-vault-client/src/ts/request.ts:172](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c392ccb/packages/cloud-vault-client/src/ts/request.ts#L172)

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

[cloud-vault-client/src/ts/request.ts:173](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c392ccb/packages/cloud-vault-client/src/ts/request.ts#L173)

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

[cloud-vault-client/src/ts/request.ts:184](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c392ccb/packages/cloud-vault-client/src/ts/request.ts#L184)

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

[cloud-vault-client/src/ts/request.ts:185](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c392ccb/packages/cloud-vault-client/src/ts/request.ts#L185)

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

[cloud-vault-client/src/ts/request.ts:203](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c392ccb/packages/cloud-vault-client/src/ts/request.ts#L203)

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

[cloud-vault-client/src/ts/request.ts:204](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c392ccb/packages/cloud-vault-client/src/ts/request.ts#L204)

___

### stop

▸ **stop**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

[cloud-vault-client/src/ts/request.ts:91](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c392ccb/packages/cloud-vault-client/src/ts/request.ts#L91)

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

[cloud-vault-client/src/ts/request.ts:77](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/c392ccb/packages/cloud-vault-client/src/ts/request.ts#L77)
