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

[src/ts/wallet/base-wallet.ts:87](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L87)

## Properties

### dialog

• **dialog**: [`Dialog`](../interfaces/Dialog.md)

#### Defined in

[src/ts/wallet/base-wallet.ts:77](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L77)

___

### keyWallet

• `Protected` **keyWallet**: [`KeyWallet`](../interfaces/KeyWallet.md)<`Uint8Array`\>

#### Defined in

[src/ts/wallet/base-wallet.ts:82](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L82)

___

### provider

• `Protected` **provider**: `string`

#### Defined in

[src/ts/wallet/base-wallet.ts:84](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L84)

___

### providersData

• `Protected` **providersData**: `Record`<`string`, [`ProviderData`](../interfaces/ProviderData.md)\>

#### Defined in

[src/ts/wallet/base-wallet.ts:85](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L85)

___

### resourceValidator

• `Protected` **resourceValidator**: `ResourceValidator`

#### Defined in

[src/ts/wallet/base-wallet.ts:83](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L83)

___

### store

• **store**: [`Store`](../interfaces/Store.md)<`Model`\>

#### Defined in

[src/ts/wallet/base-wallet.ts:78](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L78)

___

### toast

• **toast**: [`Toast`](../interfaces/Toast.md)

#### Defined in

[src/ts/wallet/base-wallet.ts:79](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L79)

___

### veramo

• **veramo**: [`Veramo`](Veramo.md)<`Model`\>

#### Defined in

[src/ts/wallet/base-wallet.ts:80](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L80)

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

[src/ts/wallet/base-wallet.ts:481](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L481)

___

### createTransaction

▸ **createTransaction**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

[src/ts/wallet/base-wallet.ts:199](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L199)

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

[src/ts/wallet/base-wallet.ts:757](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L757)

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

[src/ts/wallet/base-wallet.ts:731](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L731)

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

[src/ts/wallet/base-wallet.ts:972](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L972)

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

[src/ts/wallet/base-wallet.ts:100](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L100)

___

### getIdentities

▸ **getIdentities**(): `Promise`<{ `[did: string]`: [`Identity`](../API.md#identity);  }\>

Gets a list of identities managed by this wallet

#### Returns

`Promise`<{ `[did: string]`: [`Identity`](../API.md#identity);  }\>

#### Implementation of

Wallet.getIdentities

#### Defined in

[src/ts/wallet/base-wallet.ts:491](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L491)

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

[src/ts/wallet/base-wallet.ts:477](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L477)

___

### getResources

▸ **getResources**(): `Promise`<{ `[id: string]`: [`Resource`](../API.md#resource);  }\>

Get resources stored in the wallet's vault. It is the place where to find stored verfiable credentials, agreements, non-repudiable proofs.

#### Returns

`Promise`<{ `[id: string]`: [`Resource`](../API.md#resource);  }\>

#### Implementation of

Wallet.getResources

#### Defined in

[src/ts/wallet/base-wallet.ts:619](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L619)

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

[src/ts/wallet/base-wallet.ts:512](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L512)

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

[src/ts/wallet/base-wallet.ts:611](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L611)

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

[src/ts/wallet/base-wallet.ts:598](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L598)

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

[src/ts/wallet/base-wallet.ts:501](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L501)

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

[src/ts/wallet/base-wallet.ts:521](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L521)

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

[src/ts/wallet/base-wallet.ts:532](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L532)

___

### providerinfoGet

▸ **providerinfoGet**(): `Promise`<`ProviderData`\>

Retrieves information regarding the current connection to the DLT.

#### Returns

`Promise`<`ProviderData`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[providerinfoGet](../interfaces/Wallet.md#providerinfoget)

#### Defined in

[src/ts/wallet/base-wallet.ts:985](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L985)

___

### queryBalance

▸ **queryBalance**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

[src/ts/wallet/base-wallet.ts:166](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L166)

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

[src/ts/wallet/base-wallet.ts:782](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L782)

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

[src/ts/wallet/base-wallet.ts:675](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L675)

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

[src/ts/wallet/base-wallet.ts:290](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L290)

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

[src/ts/wallet/base-wallet.ts:276](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L276)

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

[src/ts/wallet/base-wallet.ts:922](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L922)

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

[src/ts/wallet/base-wallet.ts:956](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L956)

___

### wipe

▸ **wipe**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Implementation of

Wallet.wipe

#### Defined in

[src/ts/wallet/base-wallet.ts:258](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/37673c9/packages/base-wallet/src/ts/wallet/base-wallet.ts#L258)
