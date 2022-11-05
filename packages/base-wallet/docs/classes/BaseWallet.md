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

[base-wallet/src/ts/wallet/base-wallet.ts:84](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L84)

## Properties

### dialog

• **dialog**: [`Dialog`](../interfaces/Dialog.md)

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:74](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L74)

___

### keyWallet

• `Protected` **keyWallet**: [`KeyWallet`](../interfaces/KeyWallet.md)<`Uint8Array`\>

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:79](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L79)

___

### provider

• `Protected` **provider**: `string`

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:81](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L81)

___

### providersData

• `Protected` **providersData**: `Record`<`string`, [`ProviderData`](../API.md#providerdata)\>

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:82](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L82)

___

### resourceValidator

• `Protected` **resourceValidator**: `ResourceValidator`

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:80](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L80)

___

### store

• **store**: [`Store`](../interfaces/Store.md)<`Model`\>

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:75](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L75)

___

### toast

• **toast**: [`Toast`](../interfaces/Toast.md)

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:76](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L76)

___

### veramo

• **veramo**: [`Veramo`](Veramo.md)<`Model`\>

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:77](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L77)

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

[base-wallet/src/ts/wallet/base-wallet.ts:438](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L438)

___

### createTransaction

▸ **createTransaction**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:159](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L159)

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

[base-wallet/src/ts/wallet/base-wallet.ts:672](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L672)

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

[base-wallet/src/ts/wallet/base-wallet.ts:646](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L646)

___

### didJwtVerify

▸ **didJwtVerify**(`requestBody`): `Promise`<`$200`\>

Verifies a JWT resolving the public key from the signer DID (no other kind of signer supported) and optionally check values for expected payload claims.

The Wallet only supports the 'ES256K1' algorithm.

Useful to verify JWT created by another wallet instance.

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `RequestBody` |

#### Returns

`Promise`<`$200`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[didJwtVerify](../interfaces/Wallet.md#didjwtverify)

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:831](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L831)

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

[base-wallet/src/ts/wallet/base-wallet.ts:97](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L97)

___

### getIdentities

▸ **getIdentities**(): `Promise`<{ `[did: string]`: [`Identity`](../API.md#identity);  }\>

Gets a list of identities managed by this wallet

#### Returns

`Promise`<{ `[did: string]`: [`Identity`](../API.md#identity);  }\>

#### Implementation of

Wallet.getIdentities

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:448](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L448)

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

[base-wallet/src/ts/wallet/base-wallet.ts:434](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L434)

___

### getResources

▸ **getResources**(): `Promise`<{ `[id: string]`: [`Resource`](../API.md#resource);  }\>

Gets a resource stored in the wallet's vault. It is the place where to find stored verfiable credentials, agreements, non-repudiable proofs.

#### Returns

`Promise`<{ `[id: string]`: [`Resource`](../API.md#resource);  }\>

#### Implementation of

Wallet.getResources

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:576](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L576)

___

### identityCreate

▸ **identityCreate**(`requestBody`): `Promise`<`$201`\>

Creates an identity

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `RequestBody` |

#### Returns

`Promise`<`$201`\>

the DID of the created identity

#### Implementation of

[Wallet](../interfaces/Wallet.md).[identityCreate](../interfaces/Wallet.md#identitycreate)

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:469](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L469)

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

[base-wallet/src/ts/wallet/base-wallet.ts:568](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L568)

___

### identityInfo

▸ **identityInfo**(`pathParameters`): `Promise`<`$200`\>

Returns info regarding an identity. It includes DLT addresses bounded to the identity

#### Parameters

| Name | Type |
| :------ | :------ |
| `pathParameters` | `PathParameters` |

#### Returns

`Promise`<`$200`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[identityInfo](../interfaces/Wallet.md#identityinfo)

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:555](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L555)

___

### identityList

▸ **identityList**(`queryParameters`): `Promise`<`$200`\>

Returns a list of DIDs managed by this wallet

#### Parameters

| Name | Type |
| :------ | :------ |
| `queryParameters` | `QueryParameters` |

#### Returns

`Promise`<`$200`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[identityList](../interfaces/Wallet.md#identitylist)

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:458](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L458)

___

### identitySelect

▸ **identitySelect**(`queryParameters`): `Promise`<`$200`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `queryParameters` | `QueryParameters` |

#### Returns

`Promise`<`$200`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[identitySelect](../interfaces/Wallet.md#identityselect)

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:478](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L478)

___

### identitySign

▸ **identitySign**(`pathParameters`, `requestBody`): `Promise`<`$200`\>

Signs using the identity set in pathParameters. Currently suporting RAW signatures of base64url-encoded data, arbritrary JSON objects (it returns a JWT); and transactions for the DLT.

#### Parameters

| Name | Type |
| :------ | :------ |
| `pathParameters` | `PathParameters` |
| `requestBody` | `RequestBody` |

#### Returns

`Promise`<`$200`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[identitySign](../interfaces/Wallet.md#identitysign)

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:489](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L489)

___

### providerinfoGet

▸ **providerinfoGet**(): `Promise`<`$200`\>

Retrieves information regarding the current connection to the DLT.

#### Returns

`Promise`<`$200`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[providerinfoGet](../interfaces/Wallet.md#providerinfoget)

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:844](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L844)

___

### queryBalance

▸ **queryBalance**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:129](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L129)

___

### resourceCreate

▸ **resourceCreate**(`requestBody`): `Promise`<`$201`\>

Securely stores in the wallet a new resource.

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `RequestBody` |

#### Returns

`Promise`<`$201`\>

and identifier of the created resource

#### Implementation of

[Wallet](../interfaces/Wallet.md).[resourceCreate](../interfaces/Wallet.md#resourcecreate)

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:697](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L697)

___

### resourceList

▸ **resourceList**(`query`): `Promise`<`$200`\>

Gets a list of resources stored in the wallet's vault.

#### Parameters

| Name | Type |
| :------ | :------ |
| `query` | `QueryParameters` |

#### Returns

`Promise`<`$200`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[resourceList](../interfaces/Wallet.md#resourcelist)

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:604](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L604)

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

[base-wallet/src/ts/wallet/base-wallet.ts:247](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L247)

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

[base-wallet/src/ts/wallet/base-wallet.ts:233](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L233)

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

[base-wallet/src/ts/wallet/base-wallet.ts:789](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L789)

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

[base-wallet/src/ts/wallet/base-wallet.ts:815](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L815)

___

### wipe

▸ **wipe**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Implementation of

Wallet.wipe

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:215](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/518fa3f/packages/base-wallet/src/ts/wallet/base-wallet.ts#L215)
