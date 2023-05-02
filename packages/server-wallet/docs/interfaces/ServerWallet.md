# Interface: ServerWallet

## Hierarchy

- `BokWallet`

  ↳ **`ServerWallet`**

## Table of contents

### Properties

- [confirmations](ServerWallet.md#confirmations)
- [dialog](ServerWallet.md#dialog)
- [keyWallet](ServerWallet.md#keywallet)
- [provider](ServerWallet.md#provider)
- [providersData](ServerWallet.md#providersdata)
- [resourceValidator](ServerWallet.md#resourcevalidator)
- [store](ServerWallet.md#store)
- [toast](ServerWallet.md#toast)
- [veramo](ServerWallet.md#veramo)

### Methods

- [call](ServerWallet.md#call)
- [createTransaction](ServerWallet.md#createtransaction)
- [deleteIdentity](ServerWallet.md#deleteidentity)
- [deleteResource](ServerWallet.md#deleteresource)
- [didJwtVerify](ServerWallet.md#didjwtverify)
- [executeTransaction](ServerWallet.md#executetransaction)
- [getIdentities](ServerWallet.md#getidentities)
- [getKeyWallet](ServerWallet.md#getkeywallet)
- [getResources](ServerWallet.md#getresources)
- [identityCreate](ServerWallet.md#identitycreate)
- [identityDeployTransaction](ServerWallet.md#identitydeploytransaction)
- [identityInfo](ServerWallet.md#identityinfo)
- [identityList](ServerWallet.md#identitylist)
- [identitySelect](ServerWallet.md#identityselect)
- [identitySign](ServerWallet.md#identitysign)
- [importDid](ServerWallet.md#importdid)
- [providerinfoGet](ServerWallet.md#providerinfoget)
- [queryBalance](ServerWallet.md#querybalance)
- [resourceCreate](ServerWallet.md#resourcecreate)
- [resourceList](ServerWallet.md#resourcelist)
- [selectCredentialsForSdr](ServerWallet.md#selectcredentialsforsdr)
- [selectIdentity](ServerWallet.md#selectidentity)
- [selectiveDisclosure](ServerWallet.md#selectivedisclosure)
- [transactionDeploy](ServerWallet.md#transactiondeploy)
- [wipe](ServerWallet.md#wipe)

## Properties

### confirmations

• `Protected` **confirmations**: `Record`<`string`, `boolean`\>

#### Inherited from

BokWallet.confirmations

#### Defined in

[base-wallet/dist/index.d.ts:272](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L272)

___

### dialog

• **dialog**: `NullDialog`

#### Overrides

BokWallet.dialog

#### Defined in

[server-wallet/src/ts/index.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/server-wallet/src/ts/index.ts#L10)

___

### keyWallet

• `Protected` **keyWallet**: `KeyWallet`<`Uint8Array`\>

#### Inherited from

BokWallet.keyWallet

#### Defined in

[base-wallet/dist/index.d.ts:268](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L268)

___

### provider

• `Protected` **provider**: `string`

#### Inherited from

BokWallet.provider

#### Defined in

[base-wallet/dist/index.d.ts:270](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L270)

___

### providersData

• `Protected` **providersData**: `Record`<`string`, `ProviderData`\>

#### Inherited from

BokWallet.providersData

#### Defined in

[base-wallet/dist/index.d.ts:271](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L271)

___

### resourceValidator

• `Protected` **resourceValidator**: `ResourceValidator`

#### Inherited from

BokWallet.resourceValidator

#### Defined in

[base-wallet/dist/index.d.ts:269](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L269)

___

### store

• **store**: `FileStore`<`BokWalletModel`\>

#### Overrides

BokWallet.store

#### Defined in

[server-wallet/src/ts/index.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/server-wallet/src/ts/index.ts#L11)

___

### toast

• **toast**: `ConsoleToast`

#### Overrides

BokWallet.toast

#### Defined in

[server-wallet/src/ts/index.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/server-wallet/src/ts/index.ts#L12)

___

### veramo

• **veramo**: `Veramo`<`BaseWalletModel`\>

#### Inherited from

BokWallet.veramo

#### Defined in

[base-wallet/dist/index.d.ts:267](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L267)

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

BokWallet.call

#### Defined in

[base-wallet/dist/index.d.ts:281](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L281)

___

### createTransaction

▸ **createTransaction**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Inherited from

BokWallet.createTransaction

#### Defined in

[base-wallet/dist/index.d.ts:276](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L276)

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

BokWallet.deleteIdentity

#### Defined in

[base-wallet/dist/index.d.ts:294](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L294)

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

BokWallet.deleteResource

#### Defined in

[base-wallet/dist/index.d.ts:293](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L293)

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

BokWallet.didJwtVerify

#### Defined in

[base-wallet/dist/index.d.ts:298](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L298)

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

BokWallet.executeTransaction

#### Defined in

[base-wallet/dist/index.d.ts:274](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L274)

___

### getIdentities

▸ **getIdentities**(): `Promise`<{ `[did: string]`: `Identity`;  }\>

#### Returns

`Promise`<{ `[did: string]`: `Identity`;  }\>

#### Inherited from

BokWallet.getIdentities

#### Defined in

[base-wallet/dist/index.d.ts:282](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L282)

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

BokWallet.getKeyWallet

#### Defined in

[base-wallet/dist/index.d.ts:280](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L280)

___

### getResources

▸ **getResources**(): `Promise`<{ `[id: string]`: `Resource$1`;  }\>

#### Returns

`Promise`<{ `[id: string]`: `Resource$1`;  }\>

#### Inherited from

BokWallet.getResources

#### Defined in

[base-wallet/dist/index.d.ts:289](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L289)

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

BokWallet.identityCreate

#### Defined in

[base-wallet/dist/index.d.ts:284](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L284)

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

BokWallet.identityDeployTransaction

#### Defined in

[base-wallet/dist/index.d.ts:288](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L288)

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

BokWallet.identityInfo

#### Defined in

[base-wallet/dist/index.d.ts:287](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L287)

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

BokWallet.identityList

#### Defined in

[base-wallet/dist/index.d.ts:283](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L283)

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

BokWallet.identitySelect

#### Defined in

[base-wallet/dist/index.d.ts:285](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L285)

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

BokWallet.identitySign

#### Defined in

[base-wallet/dist/index.d.ts:286](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L286)

___

### importDid

▸ **importDid**(`importInfo?`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `importInfo?` | `ImportInfo` |

#### Returns

`Promise`<`void`\>

#### Inherited from

BokWallet.importDid

#### Defined in

[bok-wallet/dist/index.d.ts:23](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/bok-wallet/dist/index.d.ts#L23)

___

### providerinfoGet

▸ **providerinfoGet**(): `Promise`<`ProviderData`\>

#### Returns

`Promise`<`ProviderData`\>

#### Inherited from

BokWallet.providerinfoGet

#### Defined in

[base-wallet/dist/index.d.ts:299](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L299)

___

### queryBalance

▸ **queryBalance**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Inherited from

BokWallet.queryBalance

#### Defined in

[base-wallet/dist/index.d.ts:275](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L275)

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

BokWallet.resourceCreate

#### Defined in

[base-wallet/dist/index.d.ts:295](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L295)

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

BokWallet.resourceList

#### Defined in

[base-wallet/dist/index.d.ts:292](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L292)

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

BokWallet.selectCredentialsForSdr

#### Defined in

[base-wallet/dist/index.d.ts:279](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L279)

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

BokWallet.selectIdentity

#### Defined in

[base-wallet/dist/index.d.ts:278](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L278)

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

BokWallet.selectiveDisclosure

#### Defined in

[base-wallet/dist/index.d.ts:296](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L296)

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

BokWallet.transactionDeploy

#### Defined in

[base-wallet/dist/index.d.ts:297](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L297)

___

### wipe

▸ **wipe**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Inherited from

BokWallet.wipe

#### Defined in

[base-wallet/dist/index.d.ts:277](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3b/packages/base-wallet/dist/index.d.ts#L277)
