# Interface: Wallet

## Implemented by

- [`BaseWallet`](../classes/BaseWallet.md)

## Table of contents

### Properties

- [call](Wallet.md#call)
- [deleteIdentity](Wallet.md#deleteidentity)
- [deleteResource](Wallet.md#deleteresource)
- [getIdentities](Wallet.md#getidentities)
- [getResources](Wallet.md#getresources)
- [wipe](Wallet.md#wipe)

### Methods

- [didJwtVerify](Wallet.md#didjwtverify)
- [identityCreate](Wallet.md#identitycreate)
- [identityDeployTransaction](Wallet.md#identitydeploytransaction)
- [identityInfo](Wallet.md#identityinfo)
- [identityList](Wallet.md#identitylist)
- [identitySelect](Wallet.md#identityselect)
- [identitySign](Wallet.md#identitysign)
- [providerinfoGet](Wallet.md#providerinfoget)
- [resourceCreate](Wallet.md#resourcecreate)
- [resourceList](Wallet.md#resourcelist)
- [selectiveDisclosure](Wallet.md#selectivedisclosure)
- [transactionDeploy](Wallet.md#transactiondeploy)

## Properties

### call

• **call**: (`functionMetadata`: [`WalletFunctionMetadata`](WalletFunctionMetadata.md)) => `Promise`<`void`\>

#### Type declaration

▸ (`functionMetadata`): `Promise`<`void`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `functionMetadata` | [`WalletFunctionMetadata`](WalletFunctionMetadata.md) |

##### Returns

`Promise`<`void`\>

#### Defined in

[base-wallet/src/ts/wallet/wallet.ts:7](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38dde2b/packages/base-wallet/src/ts/wallet/wallet.ts#L7)

___

### deleteIdentity

• **deleteIdentity**: (`did`: `string`) => `Promise`<`void`\>

#### Type declaration

▸ (`did`): `Promise`<`void`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `did` | `string` |

##### Returns

`Promise`<`void`\>

#### Defined in

[base-wallet/src/ts/wallet/wallet.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38dde2b/packages/base-wallet/src/ts/wallet/wallet.ts#L13)

___

### deleteResource

• **deleteResource**: (`id`: `string`) => `Promise`<`void`\>

#### Type declaration

▸ (`id`): `Promise`<`void`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `id` | `string` |

##### Returns

`Promise`<`void`\>

#### Defined in

[base-wallet/src/ts/wallet/wallet.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38dde2b/packages/base-wallet/src/ts/wallet/wallet.ts#L12)

___

### getIdentities

• **getIdentities**: () => `Promise`<{ `[did: string]`: [`Identity`](../API.md#identity);  }\>

#### Type declaration

▸ (): `Promise`<{ `[did: string]`: [`Identity`](../API.md#identity);  }\>

##### Returns

`Promise`<{ `[did: string]`: [`Identity`](../API.md#identity);  }\>

#### Defined in

[base-wallet/src/ts/wallet/wallet.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38dde2b/packages/base-wallet/src/ts/wallet/wallet.ts#L10)

___

### getResources

• **getResources**: () => `Promise`<{ `[id: string]`: [`Resource`](../API.md#resource);  }\>

#### Type declaration

▸ (): `Promise`<{ `[id: string]`: [`Resource`](../API.md#resource);  }\>

##### Returns

`Promise`<{ `[id: string]`: [`Resource`](../API.md#resource);  }\>

#### Defined in

[base-wallet/src/ts/wallet/wallet.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38dde2b/packages/base-wallet/src/ts/wallet/wallet.ts#L9)

___

### wipe

• **wipe**: () => `Promise`<`void`\>

#### Type declaration

▸ (): `Promise`<`void`\>

##### Returns

`Promise`<`void`\>

#### Defined in

[base-wallet/src/ts/wallet/wallet.ts:15](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38dde2b/packages/base-wallet/src/ts/wallet/wallet.ts#L15)

## Methods

### didJwtVerify

▸ **didJwtVerify**(`requestBody`): `Promise`<`$200`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `RequestBody` |

#### Returns

`Promise`<`$200`\>

#### Defined in

[base-wallet/src/ts/wallet/wallet.ts:27](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38dde2b/packages/base-wallet/src/ts/wallet/wallet.ts#L27)

___

### identityCreate

▸ **identityCreate**(`requestBody`): `Promise`<`$201`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `RequestBody` |

#### Returns

`Promise`<`$201`\>

#### Defined in

[base-wallet/src/ts/wallet/wallet.ts:18](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38dde2b/packages/base-wallet/src/ts/wallet/wallet.ts#L18)

___

### identityDeployTransaction

▸ **identityDeployTransaction**(`pathParameters`, `requestBody`): `Promise`<`$200`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `pathParameters` | `PathParameters` |
| `requestBody` | `RequestBody` |

#### Returns

`Promise`<`$200`\>

#### Defined in

[base-wallet/src/ts/wallet/wallet.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38dde2b/packages/base-wallet/src/ts/wallet/wallet.ts#L22)

___

### identityInfo

▸ **identityInfo**(`pathParameters`): `Promise`<`$200`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `pathParameters` | `PathParameters` |

#### Returns

`Promise`<`$200`\>

#### Defined in

[base-wallet/src/ts/wallet/wallet.ts:21](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38dde2b/packages/base-wallet/src/ts/wallet/wallet.ts#L21)

___

### identityList

▸ **identityList**(`queryParameters`): `Promise`<`$200`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `queryParameters` | `QueryParameters` |

#### Returns

`Promise`<`$200`\>

#### Defined in

[base-wallet/src/ts/wallet/wallet.ts:17](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38dde2b/packages/base-wallet/src/ts/wallet/wallet.ts#L17)

___

### identitySelect

▸ **identitySelect**(`queryParameters`): `Promise`<`$200`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `queryParameters` | `QueryParameters` |

#### Returns

`Promise`<`$200`\>

#### Defined in

[base-wallet/src/ts/wallet/wallet.ts:19](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38dde2b/packages/base-wallet/src/ts/wallet/wallet.ts#L19)

___

### identitySign

▸ **identitySign**(`pathParameters`, `requestBody`): `Promise`<`$200`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `pathParameters` | `PathParameters` |
| `requestBody` | `RequestBody` |

#### Returns

`Promise`<`$200`\>

#### Defined in

[base-wallet/src/ts/wallet/wallet.ts:20](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38dde2b/packages/base-wallet/src/ts/wallet/wallet.ts#L20)

___

### providerinfoGet

▸ **providerinfoGet**(): `Promise`<`$200`\>

#### Returns

`Promise`<`$200`\>

#### Defined in

[base-wallet/src/ts/wallet/wallet.ts:28](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38dde2b/packages/base-wallet/src/ts/wallet/wallet.ts#L28)

___

### resourceCreate

▸ **resourceCreate**(`requestBody`): `Promise`<`$201`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `RequestBody` |

#### Returns

`Promise`<`$201`\>

#### Defined in

[base-wallet/src/ts/wallet/wallet.ts:24](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38dde2b/packages/base-wallet/src/ts/wallet/wallet.ts#L24)

___

### resourceList

▸ **resourceList**(`queryParameters`): `Promise`<`$200`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `queryParameters` | `QueryParameters` |

#### Returns

`Promise`<`$200`\>

#### Defined in

[base-wallet/src/ts/wallet/wallet.ts:23](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38dde2b/packages/base-wallet/src/ts/wallet/wallet.ts#L23)

___

### selectiveDisclosure

▸ **selectiveDisclosure**(`pathParameters`): `Promise`<`$200`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `pathParameters` | `PathParameters` |

#### Returns

`Promise`<`$200`\>

#### Defined in

[base-wallet/src/ts/wallet/wallet.ts:25](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38dde2b/packages/base-wallet/src/ts/wallet/wallet.ts#L25)

___

### transactionDeploy

▸ **transactionDeploy**(`requestBody`): `Promise`<`$200`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `RequestBody` |

#### Returns

`Promise`<`$200`\>

#### Defined in

[base-wallet/src/ts/wallet/wallet.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/38dde2b/packages/base-wallet/src/ts/wallet/wallet.ts#L26)
