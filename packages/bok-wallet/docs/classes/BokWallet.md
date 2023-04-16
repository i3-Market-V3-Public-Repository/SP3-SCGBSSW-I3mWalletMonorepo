# Class: BokWallet

## Hierarchy

- `BaseWallet`<`WalletOptions`<[`BokWalletModel`](../interfaces/BokWalletModel.md)\>\>

  ↳ **`BokWallet`**

## Table of contents

### Constructors

- [constructor](BokWallet.md#constructor)

### Properties

- [dialog](BokWallet.md#dialog)
- [keyWallet](BokWallet.md#keywallet)
- [provider](BokWallet.md#provider)
- [providersData](BokWallet.md#providersdata)
- [resourceValidator](BokWallet.md#resourcevalidator)
- [store](BokWallet.md#store)
- [toast](BokWallet.md#toast)
- [veramo](BokWallet.md#veramo)

### Methods

- [call](BokWallet.md#call)
- [createTransaction](BokWallet.md#createtransaction)
- [deleteIdentity](BokWallet.md#deleteidentity)
- [deleteResource](BokWallet.md#deleteresource)
- [didJwtVerify](BokWallet.md#didjwtverify)
- [executeTransaction](BokWallet.md#executetransaction)
- [getIdentities](BokWallet.md#getidentities)
- [getKeyWallet](BokWallet.md#getkeywallet)
- [getResources](BokWallet.md#getresources)
- [identityCreate](BokWallet.md#identitycreate)
- [identityDeployTransaction](BokWallet.md#identitydeploytransaction)
- [identityInfo](BokWallet.md#identityinfo)
- [identityList](BokWallet.md#identitylist)
- [identitySelect](BokWallet.md#identityselect)
- [identitySign](BokWallet.md#identitysign)
- [importDid](BokWallet.md#importdid)
- [providerinfoGet](BokWallet.md#providerinfoget)
- [queryBalance](BokWallet.md#querybalance)
- [resourceCreate](BokWallet.md#resourcecreate)
- [resourceList](BokWallet.md#resourcelist)
- [selectCredentialsForSdr](BokWallet.md#selectcredentialsforsdr)
- [selectIdentity](BokWallet.md#selectidentity)
- [selectiveDisclosure](BokWallet.md#selectivedisclosure)
- [transactionDeploy](BokWallet.md#transactiondeploy)
- [wipe](BokWallet.md#wipe)

## Constructors

### constructor

• **new BokWallet**(`opts`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `opts` | `WalletOptions`<[`BokWalletModel`](../interfaces/BokWalletModel.md)\> |

#### Inherited from

BaseWallet<WalletOptions<BokWalletModel\>\>.constructor

#### Defined in

[base-wallet/dist/index.d.ts:272](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L272)

## Properties

### dialog

• **dialog**: `Dialog`

#### Inherited from

BaseWallet.dialog

#### Defined in

[base-wallet/dist/index.d.ts:264](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L264)

___

### keyWallet

• `Protected` **keyWallet**: `KeyWallet`<`Uint8Array`\>

#### Inherited from

BaseWallet.keyWallet

#### Defined in

[base-wallet/dist/index.d.ts:268](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L268)

___

### provider

• `Protected` **provider**: `string`

#### Inherited from

BaseWallet.provider

#### Defined in

[base-wallet/dist/index.d.ts:270](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L270)

___

### providersData

• `Protected` **providersData**: `Record`<`string`, `ProviderData`\>

#### Inherited from

BaseWallet.providersData

#### Defined in

[base-wallet/dist/index.d.ts:271](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L271)

___

### resourceValidator

• `Protected` **resourceValidator**: `ResourceValidator`

#### Inherited from

BaseWallet.resourceValidator

#### Defined in

[base-wallet/dist/index.d.ts:269](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L269)

___

### store

• **store**: `Store`<`BaseWalletModel`\>

#### Inherited from

BaseWallet.store

#### Defined in

[base-wallet/dist/index.d.ts:265](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L265)

___

### toast

• **toast**: `Toast`

#### Inherited from

BaseWallet.toast

#### Defined in

[base-wallet/dist/index.d.ts:266](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L266)

___

### veramo

• **veramo**: `Veramo`<`BaseWalletModel`\>

#### Inherited from

BaseWallet.veramo

#### Defined in

[base-wallet/dist/index.d.ts:267](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L267)

## Methods

### call

▸ **call**(`functionMetadata`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `functionMetadata` | `WalletFunctionMetadata` |

#### Returns

`Promise`<`void`\>

#### Inherited from

BaseWallet.call

#### Defined in

[base-wallet/dist/index.d.ts:280](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L280)

___

### createTransaction

▸ **createTransaction**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Inherited from

BaseWallet.createTransaction

#### Defined in

[base-wallet/dist/index.d.ts:275](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L275)

___

### deleteIdentity

▸ **deleteIdentity**(`did`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `did` | `string` |

#### Returns

`Promise`<`void`\>

#### Inherited from

BaseWallet.deleteIdentity

#### Defined in

[base-wallet/dist/index.d.ts:293](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L293)

___

### deleteResource

▸ **deleteResource**(`id`, `requestConfirmation?`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `id` | `string` |
| `requestConfirmation?` | `boolean` |

#### Returns

`Promise`<`void`\>

#### Inherited from

BaseWallet.deleteResource

#### Defined in

[base-wallet/dist/index.d.ts:292](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L292)

___

### didJwtVerify

▸ **didJwtVerify**(`requestBody`): `Promise`<`VerificationOutput`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `RequestBody` |

#### Returns

`Promise`<`VerificationOutput`\>

#### Inherited from

BaseWallet.didJwtVerify

#### Defined in

[base-wallet/dist/index.d.ts:297](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L297)

___

### executeTransaction

▸ **executeTransaction**(`options?`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `options?` | `TransactionOptions` |

#### Returns

`Promise`<`void`\>

#### Inherited from

BaseWallet.executeTransaction

#### Defined in

[base-wallet/dist/index.d.ts:273](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L273)

___

### getIdentities

▸ **getIdentities**(): `Promise`<{ `[did: string]`: `Identity`;  }\>

#### Returns

`Promise`<{ `[did: string]`: `Identity`;  }\>

#### Inherited from

BaseWallet.getIdentities

#### Defined in

[base-wallet/dist/index.d.ts:281](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L281)

___

### getKeyWallet

▸ **getKeyWallet**<`T`\>(): `T`

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends `KeyWallet`<`Uint8Array`, `T`\> |

#### Returns

`T`

#### Inherited from

BaseWallet.getKeyWallet

#### Defined in

[base-wallet/dist/index.d.ts:279](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L279)

___

### getResources

▸ **getResources**(): `Promise`<{ `[id: string]`: `Resource$1`;  }\>

#### Returns

`Promise`<{ `[id: string]`: `Resource$1`;  }\>

#### Inherited from

BaseWallet.getResources

#### Defined in

[base-wallet/dist/index.d.ts:288](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L288)

___

### identityCreate

▸ **identityCreate**(`requestBody`): `Promise`<`IdentityCreateOutput`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `IdentityCreateInput` |

#### Returns

`Promise`<`IdentityCreateOutput`\>

#### Inherited from

BaseWallet.identityCreate

#### Defined in

[base-wallet/dist/index.d.ts:283](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L283)

___

### identityDeployTransaction

▸ **identityDeployTransaction**(`pathParameters`, `requestBody`): `Promise`<`Receipt`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `pathParameters` | `PathParameters` |
| `requestBody` | `Transaction` |

#### Returns

`Promise`<`Receipt`\>

#### Inherited from

BaseWallet.identityDeployTransaction

#### Defined in

[base-wallet/dist/index.d.ts:287](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L287)

___

### identityInfo

▸ **identityInfo**(`pathParameters`): `Promise`<`IdentityData`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `pathParameters` | `PathParameters` |

#### Returns

`Promise`<`IdentityData`\>

#### Inherited from

BaseWallet.identityInfo

#### Defined in

[base-wallet/dist/index.d.ts:286](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L286)

___

### identityList

▸ **identityList**(`queryParameters`): `Promise`<`IdentityListInput`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `queryParameters` | `QueryParameters` |

#### Returns

`Promise`<`IdentityListInput`\>

#### Inherited from

BaseWallet.identityList

#### Defined in

[base-wallet/dist/index.d.ts:282](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L282)

___

### identitySelect

▸ **identitySelect**(`queryParameters`): `Promise`<`IdentitySelectOutput`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `queryParameters` | `QueryParameters` |

#### Returns

`Promise`<`IdentitySelectOutput`\>

#### Inherited from

BaseWallet.identitySelect

#### Defined in

[base-wallet/dist/index.d.ts:284](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L284)

___

### identitySign

▸ **identitySign**(`pathParameters`, `requestBody`): `Promise`<`SignOutput`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `pathParameters` | `PathParameters` |
| `requestBody` | `SignInput` |

#### Returns

`Promise`<`SignOutput`\>

#### Inherited from

BaseWallet.identitySign

#### Defined in

[base-wallet/dist/index.d.ts:285](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L285)

___

### importDid

▸ **importDid**(`importInfo?`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `importInfo?` | `ImportInfo` |

#### Returns

`Promise`<`void`\>

#### Defined in

[bok-wallet/src/ts/bok-wallet.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/bok-wallet/src/ts/bok-wallet.ts#L12)

___

### providerinfoGet

▸ **providerinfoGet**(): `Promise`<`ProviderData`\>

#### Returns

`Promise`<`ProviderData`\>

#### Inherited from

BaseWallet.providerinfoGet

#### Defined in

[base-wallet/dist/index.d.ts:298](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L298)

___

### queryBalance

▸ **queryBalance**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Inherited from

BaseWallet.queryBalance

#### Defined in

[base-wallet/dist/index.d.ts:274](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L274)

___

### resourceCreate

▸ **resourceCreate**(`requestBody`): `Promise`<`ResourceId`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `Resource` |

#### Returns

`Promise`<`ResourceId`\>

#### Inherited from

BaseWallet.resourceCreate

#### Defined in

[base-wallet/dist/index.d.ts:294](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L294)

___

### resourceList

▸ **resourceList**(`query`): `Promise`<`ResourceListOutput`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `query` | `QueryParameters` |

#### Returns

`Promise`<`ResourceListOutput`\>

#### Inherited from

BaseWallet.resourceList

#### Defined in

[base-wallet/dist/index.d.ts:291](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L291)

___

### selectCredentialsForSdr

▸ **selectCredentialsForSdr**(`sdrMessage`): `Promise`<`undefined` \| `VerifiablePresentation`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `sdrMessage` | `IMessage` |

#### Returns

`Promise`<`undefined` \| `VerifiablePresentation`\>

#### Inherited from

BaseWallet.selectCredentialsForSdr

#### Defined in

[base-wallet/dist/index.d.ts:278](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L278)

___

### selectIdentity

▸ **selectIdentity**(`options?`): `Promise`<`IIdentifier`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `options?` | `SelectIdentityOptions` |

#### Returns

`Promise`<`IIdentifier`\>

#### Inherited from

BaseWallet.selectIdentity

#### Defined in

[base-wallet/dist/index.d.ts:277](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L277)

___

### selectiveDisclosure

▸ **selectiveDisclosure**(`pathParameters`): `Promise`<`$200`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `pathParameters` | `PathParameters` |

#### Returns

`Promise`<`$200`\>

#### Inherited from

BaseWallet.selectiveDisclosure

#### Defined in

[base-wallet/dist/index.d.ts:295](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L295)

___

### transactionDeploy

▸ **transactionDeploy**(`requestBody`): `Promise`<`$200`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `SignedTransaction` |

#### Returns

`Promise`<`$200`\>

#### Inherited from

BaseWallet.transactionDeploy

#### Defined in

[base-wallet/dist/index.d.ts:296](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L296)

___

### wipe

▸ **wipe**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Inherited from

BaseWallet.wipe

#### Defined in

[base-wallet/dist/index.d.ts:276](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/845b7ae/packages/base-wallet/dist/index.d.ts#L276)
