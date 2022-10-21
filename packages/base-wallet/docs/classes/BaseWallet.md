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
- [providerinfoGet](BaseWallet.md#providerinfoget)
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

[src/ts/wallet/base-wallet.ts:82](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L82)

## Properties

### dialog

• **dialog**: [`Dialog`](../interfaces/Dialog.md)

#### Defined in

[src/ts/wallet/base-wallet.ts:72](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L72)

___

### keyWallet

• `Protected` **keyWallet**: [`KeyWallet`](../interfaces/KeyWallet.md)<`Uint8Array`\>

#### Defined in

[src/ts/wallet/base-wallet.ts:77](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L77)

___

### provider

• `Protected` **provider**: `string`

#### Defined in

[src/ts/wallet/base-wallet.ts:79](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L79)

___

### providersData

• `Protected` **providersData**: `Record`<`string`, [`ProviderData`](../API.md#providerdata)\>

#### Defined in

[src/ts/wallet/base-wallet.ts:80](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L80)

___

### resourceValidator

• `Protected` **resourceValidator**: `ResourceValidator`

#### Defined in

[src/ts/wallet/base-wallet.ts:78](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L78)

___

### store

• **store**: [`Store`](../interfaces/Store.md)<`Model`\>

#### Defined in

[src/ts/wallet/base-wallet.ts:73](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L73)

___

### toast

• **toast**: [`Toast`](../interfaces/Toast.md)

#### Defined in

[src/ts/wallet/base-wallet.ts:74](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L74)

___

### veramo

• **veramo**: [`Veramo`](Veramo.md)<`Model`\>

#### Defined in

[src/ts/wallet/base-wallet.ts:75](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L75)

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

[src/ts/wallet/base-wallet.ts:436](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L436)

___

### createTransaction

▸ **createTransaction**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

[src/ts/wallet/base-wallet.ts:157](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L157)

___

### deleteIdentity

▸ **deleteIdentity**(`did`): `Promise`<`void`\>

Deletes a given identity (DID)

#### Parameters

| Name | Type |
| :------ | :------ |
| `did` | `string` |

#### Returns

`Promise`<`void`\>

#### Implementation of

Wallet.deleteIdentity

#### Defined in

[src/ts/wallet/base-wallet.ts:608](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L608)

___

### deleteResource

▸ **deleteResource**(`id`): `Promise`<`void`\>

Deletes a given resource

#### Parameters

| Name | Type |
| :------ | :------ |
| `id` | `string` |

#### Returns

`Promise`<`void`\>

#### Implementation of

Wallet.deleteResource

#### Defined in

[src/ts/wallet/base-wallet.ts:593](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L593)

___

### didJwtVerify

▸ **didJwtVerify**(`requestBody`): `Promise`<`VerificationOutput`\>

Verifies a JWT resolving the public key from the signer DID (no other kind of signer supported) and optionally check values for expected payload claims.

The Wallet only supports the 'ES256K1' algorithm.

Useful to verify JWT created by another wallet instance.

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `RequestBody` |

#### Returns

`Promise`<`VerificationOutput`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[didJwtVerify](../interfaces/Wallet.md#didjwtverify)

#### Defined in

[src/ts/wallet/base-wallet.ts:730](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L730)

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

[src/ts/wallet/base-wallet.ts:95](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L95)

___

### getIdentities

▸ **getIdentities**(): `Promise`<{ `[did: string]`: [`Identity`](../API.md#identity);  }\>

Gets a list of identities managed by this wallet

#### Returns

`Promise`<{ `[did: string]`: [`Identity`](../API.md#identity);  }\>

#### Implementation of

Wallet.getIdentities

#### Defined in

[src/ts/wallet/base-wallet.ts:446](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L446)

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

[src/ts/wallet/base-wallet.ts:432](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L432)

___

### getResources

▸ **getResources**(): `Promise`<{ `[id: string]`: [`Resource`](../API.md#resource);  }\>

Gets a resource securey stored in the wallet's vaulr. It is the place where to find stored verfiable credentials.

#### Returns

`Promise`<{ `[id: string]`: [`Resource`](../API.md#resource);  }\>

#### Implementation of

Wallet.getResources

#### Defined in

[src/ts/wallet/base-wallet.ts:574](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L574)

___

### identityCreate

▸ **identityCreate**(`requestBody`): `Promise`<`IdentityCreateOutput`\>

Creates an identity

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `IdentityCreateInput` |

#### Returns

`Promise`<`IdentityCreateOutput`\>

the DID of the created identity

#### Implementation of

[Wallet](../interfaces/Wallet.md).[identityCreate](../interfaces/Wallet.md#identitycreate)

#### Defined in

[src/ts/wallet/base-wallet.ts:467](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L467)

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

[src/ts/wallet/base-wallet.ts:566](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L566)

___

### identityInfo

▸ **identityInfo**(`pathParameters`): `Promise`<`IdentityData`\>

Returns info regarding an identity. It includes DLT addresses bounded to the identity

#### Parameters

| Name | Type |
| :------ | :------ |
| `pathParameters` | `PathParameters` |

#### Returns

`Promise`<`IdentityData`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[identityInfo](../interfaces/Wallet.md#identityinfo)

#### Defined in

[src/ts/wallet/base-wallet.ts:553](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L553)

___

### identityList

▸ **identityList**(`queryParameters`): `Promise`<`IdentityListInput`\>

Returns a list of DIDs managed by this wallet

#### Parameters

| Name | Type |
| :------ | :------ |
| `queryParameters` | `QueryParameters` |

#### Returns

`Promise`<`IdentityListInput`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[identityList](../interfaces/Wallet.md#identitylist)

#### Defined in

[src/ts/wallet/base-wallet.ts:456](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L456)

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

[src/ts/wallet/base-wallet.ts:476](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L476)

___

### identitySign

▸ **identitySign**(`pathParameters`, `requestBody`): `Promise`<`SignOutput`\>

Signs using the identity set in pathParameters. Currently suporting RAW signatures of base64url-encoded data, arbritrary JSON objects (it returns a JWT); and transactions for the DLT.

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

[src/ts/wallet/base-wallet.ts:487](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L487)

___

### providerinfoGet

▸ **providerinfoGet**(): `Promise`<`ProviderData`\>

Retrieves information regarding the current connection to the DLT.

#### Returns

`Promise`<`ProviderData`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[providerinfoGet](../interfaces/Wallet.md#providerinfoget)

#### Defined in

[src/ts/wallet/base-wallet.ts:783](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L783)

___

### queryBalance

▸ **queryBalance**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

[src/ts/wallet/base-wallet.ts:127](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L127)

___

### resourceCreate

▸ **resourceCreate**(`requestBody`): `Promise`<`ResourceId`\>

Securely stores in the wallet a new resource. Currently only supporting verifiable credentials, which are properly verified before storing them.

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `Resource` |

#### Returns

`Promise`<`ResourceId`\>

and identifier of the created resource

#### Implementation of

[Wallet](../interfaces/Wallet.md).[resourceCreate](../interfaces/Wallet.md#resourcecreate)

#### Defined in

[src/ts/wallet/base-wallet.ts:625](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L625)

___

### resourceList

▸ **resourceList**(): `Promise`<`ResourceListOutput`\>

Gets a list of resources (currently just verifiable credentials) stored in the wallet's vault.

#### Returns

`Promise`<`ResourceListOutput`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[resourceList](../interfaces/Wallet.md#resourcelist)

#### Defined in

[src/ts/wallet/base-wallet.ts:582](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L582)

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

[src/ts/wallet/base-wallet.ts:245](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L245)

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

[src/ts/wallet/base-wallet.ts:231](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L231)

___

### selectiveDisclosure

▸ **selectiveDisclosure**(`pathParameters`): `Promise`<`$200`\>

Initiates the flow of choosing which credentials to present after a selective disclosure request.

#### Parameters

| Name | Type |
| :------ | :------ |
| `pathParameters` | `PathParameters` |

#### Returns

`Promise`<`$200`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[selectiveDisclosure](../interfaces/Wallet.md#selectivedisclosure)

#### Defined in

[src/ts/wallet/base-wallet.ts:688](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L688)

___

### transactionDeploy

▸ **transactionDeploy**(`requestBody`): `Promise`<`$200`\>

Deploys a transaction to the connected DLT

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `SignedTransaction` |

#### Returns

`Promise`<`$200`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[transactionDeploy](../interfaces/Wallet.md#transactiondeploy)

#### Defined in

[src/ts/wallet/base-wallet.ts:714](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L714)

___

### wipe

▸ **wipe**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Implementation of

Wallet.wipe

#### Defined in

[src/ts/wallet/base-wallet.ts:213](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/3790df1/packages/base-wallet/src/ts/wallet/base-wallet.ts#L213)
