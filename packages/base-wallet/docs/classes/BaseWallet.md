# Class: BaseWallet<Options, Model\>

## Type parameters

| Name | Type |
| :------ | :------ |
| `Options` | extends [`WalletOptions`](../API.md#walletoptions)<`Model`\> |
| `Model` | extends [`BaseWalletModel`](../interfaces/BaseWalletModel.md) = [`BaseWalletModel`](../interfaces/BaseWalletModel.md) |

## Implements

- [`Wallet`](../interfaces/Wallet.md)

## Table of contents

### Constructors

- [constructor](BaseWallet.md#constructor)

### Properties

- [dialog](BaseWallet.md#dialog)
- [keyWallet](BaseWallet.md#keywallet)
- [provider](BaseWallet.md#provider)
- [providersData](BaseWallet.md#providersdata)
- [resourceValidator](BaseWallet.md#resourcevalidator)
- [store](BaseWallet.md#store)
- [toast](BaseWallet.md#toast)
- [veramo](BaseWallet.md#veramo)

### Methods

- [call](BaseWallet.md#call)
- [createTransaction](BaseWallet.md#createtransaction)
- [deleteIdentity](BaseWallet.md#deleteidentity)
- [deleteResource](BaseWallet.md#deleteresource)
- [didJwtVerify](BaseWallet.md#didjwtverify)
- [executeTransaction](BaseWallet.md#executetransaction)
- [getIdentities](BaseWallet.md#getidentities)
- [getKeyWallet](BaseWallet.md#getkeywallet)
- [getResources](BaseWallet.md#getresources)
- [identityCreate](BaseWallet.md#identitycreate)
- [identityDeployTransaction](BaseWallet.md#identitydeploytransaction)
- [identityInfo](BaseWallet.md#identityinfo)
- [identityList](BaseWallet.md#identitylist)
- [identitySelect](BaseWallet.md#identityselect)
- [identitySign](BaseWallet.md#identitysign)
- [providerinfo](BaseWallet.md#providerinfo)
- [queryBalance](BaseWallet.md#querybalance)
- [resourceCreate](BaseWallet.md#resourcecreate)
- [resourceList](BaseWallet.md#resourcelist)
- [selectCredentialsForSdr](BaseWallet.md#selectcredentialsforsdr)
- [selectIdentity](BaseWallet.md#selectidentity)
- [selectiveDisclosure](BaseWallet.md#selectivedisclosure)
- [transactionDeploy](BaseWallet.md#transactiondeploy)
- [wipe](BaseWallet.md#wipe)

## Constructors

### constructor

• **new BaseWallet**<`Options`, `Model`\>(`opts`)

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Options` | extends [`WalletOptionsSettings`](../interfaces/WalletOptionsSettings.md)<`Model`, `Options`\> & [`WalletOptionsCryptoWallet`](../interfaces/WalletOptionsCryptoWallet.md) |
| `Model` | extends [`BaseWalletModel`](../interfaces/BaseWalletModel.md) = [`BaseWalletModel`](../interfaces/BaseWalletModel.md) |

#### Parameters

| Name | Type |
| :------ | :------ |
| `opts` | `Options` |

#### Defined in

src/ts/wallet/base-wallet.ts:82

## Properties

### dialog

• **dialog**: [`Dialog`](../interfaces/Dialog.md)

#### Defined in

src/ts/wallet/base-wallet.ts:72

___

### keyWallet

• `Protected` **keyWallet**: [`KeyWallet`](../interfaces/KeyWallet.md)<`Uint8Array`\>

#### Defined in

src/ts/wallet/base-wallet.ts:77

___

### provider

• `Protected` **provider**: `string`

#### Defined in

src/ts/wallet/base-wallet.ts:79

___

### providersData

• `Protected` **providersData**: `Record`<`string`, [`ProviderData`](../API.md#providerdata)\>

#### Defined in

src/ts/wallet/base-wallet.ts:80

___

### resourceValidator

• `Protected` **resourceValidator**: `ResourceValidator`

#### Defined in

src/ts/wallet/base-wallet.ts:78

___

### store

• **store**: [`Store`](../interfaces/Store.md)<`Model`\>

#### Defined in

src/ts/wallet/base-wallet.ts:73

___

### toast

• **toast**: [`Toast`](../interfaces/Toast.md)

#### Defined in

src/ts/wallet/base-wallet.ts:74

___

### veramo

• **veramo**: [`Veramo`](Veramo.md)<`Model`\>

#### Defined in

src/ts/wallet/base-wallet.ts:75

## Methods

### call

▸ **call**(`functionMetadata`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `functionMetadata` | [`WalletFunctionMetadata`](../interfaces/WalletFunctionMetadata.md) |

#### Returns

`Promise`<`void`\>

#### Implementation of

Wallet.call

#### Defined in

src/ts/wallet/base-wallet.ts:436

___

### createTransaction

▸ **createTransaction**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

src/ts/wallet/base-wallet.ts:157

___

### deleteIdentity

▸ **deleteIdentity**(`did`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `did` | `string` |

#### Returns

`Promise`<`void`\>

#### Implementation of

Wallet.deleteIdentity

#### Defined in

src/ts/wallet/base-wallet.ts:564

___

### deleteResource

▸ **deleteResource**(`id`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `id` | `string` |

#### Returns

`Promise`<`void`\>

#### Implementation of

Wallet.deleteResource

#### Defined in

src/ts/wallet/base-wallet.ts:553

___

### didJwtVerify

▸ **didJwtVerify**(`requestBody`): `Promise`<`VerificationOutput`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `RequestBody` |

#### Returns

`Promise`<`VerificationOutput`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[didJwtVerify](../interfaces/Wallet.md#didjwtverify)

#### Defined in

src/ts/wallet/base-wallet.ts:637

___

### executeTransaction

▸ **executeTransaction**(`options?`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `options` | `TransactionOptions` |

#### Returns

`Promise`<`void`\>

#### Defined in

src/ts/wallet/base-wallet.ts:95

___

### getIdentities

▸ **getIdentities**(): `Promise`<{ `[did: string]`: [`Identity`](../API.md#identity);  }\>

#### Returns

`Promise`<{ `[did: string]`: [`Identity`](../API.md#identity);  }\>

#### Implementation of

Wallet.getIdentities

#### Defined in

src/ts/wallet/base-wallet.ts:441

___

### getKeyWallet

▸ **getKeyWallet**<`T`\>(): `T`

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends [`KeyWallet`](../interfaces/KeyWallet.md)<`Uint8Array`, `T`\> |

#### Returns

`T`

#### Defined in

src/ts/wallet/base-wallet.ts:432

___

### getResources

▸ **getResources**(): `Promise`<{ `[id: string]`: [`Resource`](../API.md#resource);  }\>

#### Returns

`Promise`<{ `[id: string]`: [`Resource`](../API.md#resource);  }\>

#### Implementation of

Wallet.getResources

#### Defined in

src/ts/wallet/base-wallet.ts:542

___

### identityCreate

▸ **identityCreate**(`requestBody`): `Promise`<`IdentityCreateOutput`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `IdentityCreateInput` |

#### Returns

`Promise`<`IdentityCreateOutput`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[identityCreate](../interfaces/Wallet.md#identitycreate)

#### Defined in

src/ts/wallet/base-wallet.ts:451

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

#### Implementation of

[Wallet](../interfaces/Wallet.md).[identityDeployTransaction](../interfaces/Wallet.md#identitydeploytransaction)

#### Defined in

src/ts/wallet/base-wallet.ts:538

___

### identityInfo

▸ **identityInfo**(`pathParameters`): `Promise`<`IdentityData`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `pathParameters` | `PathParameters` |

#### Returns

`Promise`<`IdentityData`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[identityInfo](../interfaces/Wallet.md#identityinfo)

#### Defined in

src/ts/wallet/base-wallet.ts:525

___

### identityList

▸ **identityList**(`queryParameters`): `Promise`<`IdentityListInput`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `queryParameters` | `QueryParameters` |

#### Returns

`Promise`<`IdentityListInput`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[identityList](../interfaces/Wallet.md#identitylist)

#### Defined in

src/ts/wallet/base-wallet.ts:445

___

### identitySelect

▸ **identitySelect**(`queryParameters`): `Promise`<`IdentitySelectOutput`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `queryParameters` | `QueryParameters` |

#### Returns

`Promise`<`IdentitySelectOutput`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[identitySelect](../interfaces/Wallet.md#identityselect)

#### Defined in

src/ts/wallet/base-wallet.ts:460

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

#### Implementation of

[Wallet](../interfaces/Wallet.md).[identitySign](../interfaces/Wallet.md#identitysign)

#### Defined in

src/ts/wallet/base-wallet.ts:465

___

### providerinfo

▸ **providerinfo**(): `Promise`<`ProviderData`\>

#### Returns

`Promise`<`ProviderData`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[providerinfo](../interfaces/Wallet.md#providerinfo)

#### Defined in

src/ts/wallet/base-wallet.ts:686

___

### queryBalance

▸ **queryBalance**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

src/ts/wallet/base-wallet.ts:127

___

### resourceCreate

▸ **resourceCreate**(`requestBody`): `Promise`<`ResourceId`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `VerifiableCredential` |

#### Returns

`Promise`<`ResourceId`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[resourceCreate](../interfaces/Wallet.md#resourcecreate)

#### Defined in

src/ts/wallet/base-wallet.ts:575

___

### resourceList

▸ **resourceList**(): `Promise`<`ResourceListOutput`\>

#### Returns

`Promise`<`ResourceListOutput`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[resourceList](../interfaces/Wallet.md#resourcelist)

#### Defined in

src/ts/wallet/base-wallet.ts:546

___

### selectCredentialsForSdr

▸ **selectCredentialsForSdr**(`sdrMessage`): `Promise`<`undefined` \| `VerifiablePresentation`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `sdrMessage` | `IMessage` |

#### Returns

`Promise`<`undefined` \| `VerifiablePresentation`\>

#### Defined in

src/ts/wallet/base-wallet.ts:245

___

### selectIdentity

▸ **selectIdentity**(`options?`): `Promise`<`IIdentifier`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `options?` | `SelectIdentityOptions` |

#### Returns

`Promise`<`IIdentifier`\>

#### Defined in

src/ts/wallet/base-wallet.ts:231

___

### selectiveDisclosure

▸ **selectiveDisclosure**(`pathParameters`): `Promise`<`$200`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `pathParameters` | `PathParameters` |

#### Returns

`Promise`<`$200`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[selectiveDisclosure](../interfaces/Wallet.md#selectivedisclosure)

#### Defined in

src/ts/wallet/base-wallet.ts:609

___

### transactionDeploy

▸ **transactionDeploy**(`requestBody`): `Promise`<`$200`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `SignedTransaction` |

#### Returns

`Promise`<`$200`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[transactionDeploy](../interfaces/Wallet.md#transactiondeploy)

#### Defined in

src/ts/wallet/base-wallet.ts:630

___

### wipe

▸ **wipe**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Implementation of

Wallet.wipe

#### Defined in

src/ts/wallet/base-wallet.ts:213
