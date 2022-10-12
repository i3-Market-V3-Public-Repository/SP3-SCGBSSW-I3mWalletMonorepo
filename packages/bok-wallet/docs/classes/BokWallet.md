# Class: BokWallet

## Hierarchy

- `BaseWallet`<`WalletOptions`<`BokWalletModel`\>\>

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
- [providerinfo](BokWallet.md#providerinfo)
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
| `opts` | `WalletOptions`<`BokWalletModel`\> |

#### Inherited from

BaseWallet<WalletOptions<BokWalletModel\>\>.constructor

#### Defined in

base-wallet/types/wallet/base-wallet.d.ts:26

## Properties

### dialog

• **dialog**: `Dialog`

#### Inherited from

BaseWallet.dialog

#### Defined in

base-wallet/types/wallet/base-wallet.d.ts:18

___

### keyWallet

• `Protected` **keyWallet**: `KeyWallet`<`Uint8Array`\>

#### Inherited from

BaseWallet.keyWallet

#### Defined in

base-wallet/types/wallet/base-wallet.d.ts:22

___

### provider

• `Protected` **provider**: `string`

#### Inherited from

BaseWallet.provider

#### Defined in

base-wallet/types/wallet/base-wallet.d.ts:24

___

### providersData

• `Protected` **providersData**: `Record`<`string`, `ProviderData`\>

#### Inherited from

BaseWallet.providersData

#### Defined in

base-wallet/types/wallet/base-wallet.d.ts:25

___

### resourceValidator

• `Protected` **resourceValidator**: `ResourceValidator`

#### Inherited from

BaseWallet.resourceValidator

#### Defined in

base-wallet/types/wallet/base-wallet.d.ts:23

___

### store

• **store**: `Store`<`BaseWalletModel`\>

#### Inherited from

BaseWallet.store

#### Defined in

base-wallet/types/wallet/base-wallet.d.ts:19

___

### toast

• **toast**: `Toast`

#### Inherited from

BaseWallet.toast

#### Defined in

base-wallet/types/wallet/base-wallet.d.ts:20

___

### veramo

• **veramo**: `default`<`BaseWalletModel`\>

#### Inherited from

BaseWallet.veramo

#### Defined in

base-wallet/types/wallet/base-wallet.d.ts:21

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

base-wallet/types/wallet/base-wallet.d.ts:34

___

### createTransaction

▸ **createTransaction**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Inherited from

BaseWallet.createTransaction

#### Defined in

base-wallet/types/wallet/base-wallet.d.ts:29

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

base-wallet/types/wallet/base-wallet.d.ts:45

___

### deleteResource

▸ **deleteResource**(`id`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `id` | `string` |

#### Returns

`Promise`<`void`\>

#### Inherited from

BaseWallet.deleteResource

#### Defined in

base-wallet/types/wallet/base-wallet.d.ts:44

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

base-wallet/types/wallet/base-wallet.d.ts:49

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

base-wallet/types/wallet/base-wallet.d.ts:27

___

### getIdentities

▸ **getIdentities**(): `Promise`<{ `[did: string]`: `Identity`;  }\>

#### Returns

`Promise`<{ `[did: string]`: `Identity`;  }\>

#### Inherited from

BaseWallet.getIdentities

#### Defined in

base-wallet/types/wallet/base-wallet.d.ts:35

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

base-wallet/types/wallet/base-wallet.d.ts:33

___

### getResources

▸ **getResources**(): `Promise`<{ `[id: string]`: `Resource`;  }\>

#### Returns

`Promise`<{ `[id: string]`: `Resource`;  }\>

#### Inherited from

BaseWallet.getResources

#### Defined in

base-wallet/types/wallet/base-wallet.d.ts:42

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

base-wallet/types/wallet/base-wallet.d.ts:37

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

base-wallet/types/wallet/base-wallet.d.ts:41

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

base-wallet/types/wallet/base-wallet.d.ts:40

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

base-wallet/types/wallet/base-wallet.d.ts:36

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

base-wallet/types/wallet/base-wallet.d.ts:38

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

base-wallet/types/wallet/base-wallet.d.ts:39

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

bok-wallet/src/ts/bok-wallet.ts:13

___

### providerinfo

▸ **providerinfo**(): `Promise`<`ProviderData`\>

#### Returns

`Promise`<`ProviderData`\>

#### Inherited from

BaseWallet.providerinfo

#### Defined in

base-wallet/types/wallet/base-wallet.d.ts:50

___

### queryBalance

▸ **queryBalance**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Inherited from

BaseWallet.queryBalance

#### Defined in

base-wallet/types/wallet/base-wallet.d.ts:28

___

### resourceCreate

▸ **resourceCreate**(`requestBody`): `Promise`<`ResourceId`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `VerifiableCredential` |

#### Returns

`Promise`<`ResourceId`\>

#### Inherited from

BaseWallet.resourceCreate

#### Defined in

base-wallet/types/wallet/base-wallet.d.ts:46

___

### resourceList

▸ **resourceList**(): `Promise`<`ResourceListOutput`\>

#### Returns

`Promise`<`ResourceListOutput`\>

#### Inherited from

BaseWallet.resourceList

#### Defined in

base-wallet/types/wallet/base-wallet.d.ts:43

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

base-wallet/types/wallet/base-wallet.d.ts:32

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

base-wallet/types/wallet/base-wallet.d.ts:31

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

base-wallet/types/wallet/base-wallet.d.ts:47

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

base-wallet/types/wallet/base-wallet.d.ts:48

___

### wipe

▸ **wipe**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Inherited from

BaseWallet.wipe

#### Defined in

base-wallet/types/wallet/base-wallet.d.ts:30
