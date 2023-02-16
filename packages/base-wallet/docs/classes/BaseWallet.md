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

[src/ts/wallet/base-wallet.ts:86](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L86)

## Properties

### dialog

• **dialog**: [`Dialog`](../interfaces/Dialog.md)

#### Defined in

[src/ts/wallet/base-wallet.ts:76](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L76)

___

### keyWallet

• `Protected` **keyWallet**: [`KeyWallet`](../interfaces/KeyWallet.md)<`Uint8Array`\>

#### Defined in

[src/ts/wallet/base-wallet.ts:81](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L81)

___

### provider

• `Protected` **provider**: `string`

#### Defined in

[src/ts/wallet/base-wallet.ts:83](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L83)

___

### providersData

• `Protected` **providersData**: `Record`<`string`, [`ProviderData`](../interfaces/ProviderData.md)\>

#### Defined in

[src/ts/wallet/base-wallet.ts:84](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L84)

___

### resourceValidator

• `Protected` **resourceValidator**: `ResourceValidator`

#### Defined in

[src/ts/wallet/base-wallet.ts:82](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L82)

___

### store

• **store**: [`Store`](../interfaces/Store.md)<`Model`\>

#### Defined in

[src/ts/wallet/base-wallet.ts:77](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L77)

___

### toast

• **toast**: [`Toast`](../interfaces/Toast.md)

#### Defined in

[src/ts/wallet/base-wallet.ts:78](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L78)

___

### veramo

• **veramo**: [`Veramo`](Veramo.md)<`Model`\>

#### Defined in

[src/ts/wallet/base-wallet.ts:79](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L79)

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

[src/ts/wallet/base-wallet.ts:454](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L454)

___

### createTransaction

▸ **createTransaction**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

[src/ts/wallet/base-wallet.ts:173](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L173)

___

### deleteIdentity

▸ **deleteIdentity**(`did`): `Promise`<`void`\>

Deletes a given identity (DID) and all its associated resources

#### Parameters

| Name | Type |
| :------ | :------ |
| `did` | `string` |

#### Returns

`Promise`<`void`\>

#### Implementation of

Wallet.deleteIdentity

#### Defined in

[src/ts/wallet/base-wallet.ts:730](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L730)

___

### deleteResource

▸ **deleteResource**(`id`, `requestConfirmation?`): `Promise`<`void`\>

Deletes a given resource and all its children

#### Parameters

| Name | Type | Default value |
| :------ | :------ | :------ |
| `id` | `string` | `undefined` |
| `requestConfirmation` | `boolean` | `true` |

#### Returns

`Promise`<`void`\>

#### Implementation of

Wallet.deleteResource

#### Defined in

[src/ts/wallet/base-wallet.ts:704](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L704)

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

[src/ts/wallet/base-wallet.ts:945](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L945)

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

[src/ts/wallet/base-wallet.ts:99](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L99)

___

### getIdentities

▸ **getIdentities**(): `Promise`<{ `[did: string]`: [`Identity`](../API.md#identity);  }\>

Gets a list of identities managed by this wallet

#### Returns

`Promise`<{ `[did: string]`: [`Identity`](../API.md#identity);  }\>

#### Implementation of

Wallet.getIdentities

#### Defined in

[src/ts/wallet/base-wallet.ts:464](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L464)

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

[src/ts/wallet/base-wallet.ts:450](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L450)

___

### getResources

▸ **getResources**(): `Promise`<{ `[id: string]`: [`Resource`](../API.md#resource);  }\>

Get resources stored in the wallet's vault. It is the place where to find stored verfiable credentials, agreements, non-repudiable proofs.

#### Returns

`Promise`<{ `[id: string]`: [`Resource`](../API.md#resource);  }\>

#### Implementation of

Wallet.getResources

#### Defined in

[src/ts/wallet/base-wallet.ts:592](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L592)

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

[src/ts/wallet/base-wallet.ts:485](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L485)

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

[src/ts/wallet/base-wallet.ts:584](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L584)

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

[src/ts/wallet/base-wallet.ts:571](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L571)

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

[src/ts/wallet/base-wallet.ts:474](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L474)

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

[src/ts/wallet/base-wallet.ts:494](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L494)

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

[src/ts/wallet/base-wallet.ts:505](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L505)

___

### providerinfoGet

▸ **providerinfoGet**(): `Promise`<`ProviderData`\>

Retrieves information regarding the current connection to the DLT.

#### Returns

`Promise`<`ProviderData`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[providerinfoGet](../interfaces/Wallet.md#providerinfoget)

#### Defined in

[src/ts/wallet/base-wallet.ts:958](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L958)

___

### queryBalance

▸ **queryBalance**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

[src/ts/wallet/base-wallet.ts:141](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L141)

___

### resourceCreate

▸ **resourceCreate**(`requestBody`): `Promise`<`ResourceId`\>

Securely stores in the wallet a new resource.

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

[src/ts/wallet/base-wallet.ts:755](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L755)

___

### resourceList

▸ **resourceList**(`query`): `Promise`<`ResourceListOutput`\>

Gets a list of resources stored in the wallet's vault.

#### Parameters

| Name | Type |
| :------ | :------ |
| `query` | `QueryParameters` |

#### Returns

`Promise`<`ResourceListOutput`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[resourceList](../interfaces/Wallet.md#resourcelist)

#### Defined in

[src/ts/wallet/base-wallet.ts:648](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L648)

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

[src/ts/wallet/base-wallet.ts:263](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L263)

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

[src/ts/wallet/base-wallet.ts:249](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L249)

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

[src/ts/wallet/base-wallet.ts:895](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L895)

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

[src/ts/wallet/base-wallet.ts:929](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L929)

___

### wipe

▸ **wipe**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Implementation of

Wallet.wipe

#### Defined in

[src/ts/wallet/base-wallet.ts:231](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/1e32caa/packages/base-wallet/src/ts/wallet/base-wallet.ts#L231)
