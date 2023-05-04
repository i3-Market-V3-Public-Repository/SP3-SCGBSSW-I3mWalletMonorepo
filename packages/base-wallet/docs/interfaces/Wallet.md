# Interface: Wallet

## Implemented by

- [`BaseWallet`](../classes/BaseWallet.md)

## Table of contents

### Properties

- [call](Wallet.md#call)
- [deleteIdentity](Wallet.md#deleteidentity)
- [deleteResource](Wallet.md#deleteresource)
- [didJwtVerify](Wallet.md#didjwtverify)
- [getIdentities](Wallet.md#getidentities)
- [getResources](Wallet.md#getresources)
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
- [wipe](Wallet.md#wipe)

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

[src/ts/wallet/wallet.ts:7](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/wallet/wallet.ts#L7)

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

[src/ts/wallet/wallet.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/wallet/wallet.ts#L13)

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

[src/ts/wallet/wallet.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/wallet/wallet.ts#L12)

___

### didJwtVerify

• **didJwtVerify**: (`requestBody`: `RequestBody`) => `Promise`<`VerificationOutput`\>

#### Type declaration

▸ (`requestBody`): `Promise`<`VerificationOutput`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `RequestBody` |

##### Returns

`Promise`<`VerificationOutput`\>

#### Defined in

[src/ts/wallet/wallet.ts:27](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/wallet/wallet.ts#L27)

___

### getIdentities

• **getIdentities**: () => `Promise`<{ `[did: string]`: [`Identity`](../API.md#identity);  }\>

#### Type declaration

▸ (): `Promise`<{ `[did: string]`: [`Identity`](../API.md#identity);  }\>

##### Returns

`Promise`<{ `[did: string]`: [`Identity`](../API.md#identity);  }\>

#### Defined in

[src/ts/wallet/wallet.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/wallet/wallet.ts#L10)

___

### getResources

• **getResources**: () => `Promise`<{ `[id: string]`: [`Resource`](../API.md#resource);  }\>

#### Type declaration

▸ (): `Promise`<{ `[id: string]`: [`Resource`](../API.md#resource);  }\>

##### Returns

`Promise`<{ `[id: string]`: [`Resource`](../API.md#resource);  }\>

#### Defined in

[src/ts/wallet/wallet.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/wallet/wallet.ts#L9)

___

### identityCreate

• **identityCreate**: (`requestBody`: `IdentityCreateInput`) => `Promise`<`IdentityCreateOutput`\>

#### Type declaration

▸ (`requestBody`): `Promise`<`IdentityCreateOutput`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `IdentityCreateInput` |

##### Returns

`Promise`<`IdentityCreateOutput`\>

#### Defined in

[src/ts/wallet/wallet.ts:18](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/wallet/wallet.ts#L18)

___

### identityDeployTransaction

• **identityDeployTransaction**: (`pathParameters`: `PathParameters`, `requestBody`: `Transaction`) => `Promise`<`Receipt`\>

#### Type declaration

▸ (`pathParameters`, `requestBody`): `Promise`<`Receipt`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `pathParameters` | `PathParameters` |
| `requestBody` | `Transaction` |

##### Returns

`Promise`<`Receipt`\>

#### Defined in

[src/ts/wallet/wallet.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/wallet/wallet.ts#L22)

___

### identityInfo

• **identityInfo**: (`pathParameters`: `PathParameters`) => `Promise`<`IdentityData`\>

#### Type declaration

▸ (`pathParameters`): `Promise`<`IdentityData`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `pathParameters` | `PathParameters` |

##### Returns

`Promise`<`IdentityData`\>

#### Defined in

[src/ts/wallet/wallet.ts:21](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/wallet/wallet.ts#L21)

___

### identityList

• **identityList**: (`queryParameters`: `QueryParameters`) => `Promise`<`IdentityListInput`\>

#### Type declaration

▸ (`queryParameters`): `Promise`<`IdentityListInput`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `queryParameters` | `QueryParameters` |

##### Returns

`Promise`<`IdentityListInput`\>

#### Defined in

[src/ts/wallet/wallet.ts:17](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/wallet/wallet.ts#L17)

___

### identitySelect

• **identitySelect**: (`queryParameters`: `QueryParameters`) => `Promise`<`IdentitySelectOutput`\>

#### Type declaration

▸ (`queryParameters`): `Promise`<`IdentitySelectOutput`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `queryParameters` | `QueryParameters` |

##### Returns

`Promise`<`IdentitySelectOutput`\>

#### Defined in

[src/ts/wallet/wallet.ts:19](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/wallet/wallet.ts#L19)

___

### identitySign

• **identitySign**: (`pathParameters`: `PathParameters`, `requestBody`: `SignInput`) => `Promise`<`SignOutput`\>

#### Type declaration

▸ (`pathParameters`, `requestBody`): `Promise`<`SignOutput`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `pathParameters` | `PathParameters` |
| `requestBody` | `SignInput` |

##### Returns

`Promise`<`SignOutput`\>

#### Defined in

[src/ts/wallet/wallet.ts:20](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/wallet/wallet.ts#L20)

___

### providerinfoGet

• **providerinfoGet**: () => `Promise`<`ProviderData`\>

#### Type declaration

▸ (): `Promise`<`ProviderData`\>

##### Returns

`Promise`<`ProviderData`\>

#### Defined in

[src/ts/wallet/wallet.ts:28](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/wallet/wallet.ts#L28)

___

### resourceCreate

• **resourceCreate**: (`requestBody`: `Resource`) => `Promise`<`ResourceId`\>

#### Type declaration

▸ (`requestBody`): `Promise`<`ResourceId`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `Resource` |

##### Returns

`Promise`<`ResourceId`\>

#### Defined in

[src/ts/wallet/wallet.ts:24](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/wallet/wallet.ts#L24)

___

### resourceList

• **resourceList**: (`queryParameters`: `QueryParameters`) => `Promise`<`ResourceListOutput`\>

#### Type declaration

▸ (`queryParameters`): `Promise`<`ResourceListOutput`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `queryParameters` | `QueryParameters` |

##### Returns

`Promise`<`ResourceListOutput`\>

#### Defined in

[src/ts/wallet/wallet.ts:23](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/wallet/wallet.ts#L23)

___

### selectiveDisclosure

• **selectiveDisclosure**: (`pathParameters`: `PathParameters`) => `Promise`<`$200`\>

#### Type declaration

▸ (`pathParameters`): `Promise`<`$200`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `pathParameters` | `PathParameters` |

##### Returns

`Promise`<`$200`\>

#### Defined in

[src/ts/wallet/wallet.ts:25](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/wallet/wallet.ts#L25)

___

### transactionDeploy

• **transactionDeploy**: (`requestBody`: `SignedTransaction`) => `Promise`<`$200`\>

#### Type declaration

▸ (`requestBody`): `Promise`<`$200`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `SignedTransaction` |

##### Returns

`Promise`<`$200`\>

#### Defined in

[src/ts/wallet/wallet.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/wallet/wallet.ts#L26)

___

### wipe

• **wipe**: () => `Promise`<`void`\>

#### Type declaration

▸ (): `Promise`<`void`\>

##### Returns

`Promise`<`void`\>

#### Defined in

[src/ts/wallet/wallet.ts:15](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/e29e1d97/packages/base-wallet/src/ts/wallet/wallet.ts#L15)
