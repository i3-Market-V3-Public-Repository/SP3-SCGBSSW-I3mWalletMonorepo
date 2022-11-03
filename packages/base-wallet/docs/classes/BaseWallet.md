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

[base-wallet/src/ts/wallet/base-wallet.ts:80](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L80)

## Properties

### dialog

• **dialog**: [`Dialog`](../interfaces/Dialog.md)

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:70](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L70)

___

### keyWallet

• `Protected` **keyWallet**: [`KeyWallet`](../interfaces/KeyWallet.md)<`Uint8Array`\>

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:75](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L75)

___

### provider

• `Protected` **provider**: `string`

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:77](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L77)

___

### providersData

• `Protected` **providersData**: `Record`<`string`, [`ProviderData`](../API.md#providerdata)\>

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:78](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L78)

___

### resourceValidator

• `Protected` **resourceValidator**: `ResourceValidator`

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:76](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L76)

___

### store

• **store**: [`Store`](../interfaces/Store.md)<`Model`\>

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:71](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L71)

___

### toast

• **toast**: [`Toast`](../interfaces/Toast.md)

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:72](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L72)

___

### veramo

• **veramo**: [`Veramo`](Veramo.md)<`Model`\>

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:73](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L73)

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

[base-wallet/src/ts/wallet/base-wallet.ts:434](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L434)

___

### createTransaction

▸ **createTransaction**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:155](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L155)

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

[base-wallet/src/ts/wallet/base-wallet.ts:637](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L637)

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

[base-wallet/src/ts/wallet/base-wallet.ts:622](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L622)

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

[base-wallet/src/ts/wallet/base-wallet.ts:768](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L768)

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

[base-wallet/src/ts/wallet/base-wallet.ts:93](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L93)

___

### getIdentities

▸ **getIdentities**(): `Promise`<{ `[did: string]`: [`Identity`](../API.md#identity);  }\>

Gets a list of identities managed by this wallet

#### Returns

`Promise`<{ `[did: string]`: [`Identity`](../API.md#identity);  }\>

#### Implementation of

Wallet.getIdentities

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:444](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L444)

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

[base-wallet/src/ts/wallet/base-wallet.ts:430](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L430)

___

### getResources

▸ **getResources**(): `Promise`<{ `[id: string]`: [`Resource`](../API.md#resource);  }\>

Gets a resource securey stored in the wallet's vaulr. It is the place where to find stored verfiable credentials.

#### Returns

`Promise`<{ `[id: string]`: [`Resource`](../API.md#resource);  }\>

#### Implementation of

Wallet.getResources

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:572](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L572)

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

[base-wallet/src/ts/wallet/base-wallet.ts:465](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L465)

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

[base-wallet/src/ts/wallet/base-wallet.ts:564](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L564)

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

[base-wallet/src/ts/wallet/base-wallet.ts:551](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L551)

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

[base-wallet/src/ts/wallet/base-wallet.ts:454](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L454)

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

[base-wallet/src/ts/wallet/base-wallet.ts:474](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L474)

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

[base-wallet/src/ts/wallet/base-wallet.ts:485](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L485)

___

### providerinfoGet

▸ **providerinfoGet**(): `Promise`<`$200`\>

Retrieves information regarding the current connection to the DLT.

#### Returns

`Promise`<`$200`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[providerinfoGet](../interfaces/Wallet.md#providerinfoget)

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:781](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L781)

___

### queryBalance

▸ **queryBalance**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:125](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L125)

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

[base-wallet/src/ts/wallet/base-wallet.ts:654](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L654)

___

### resourceList

▸ **resourceList**(`query`): `Promise`<`$200`\>

Gets a list of resources (currently just verifiable credentials) stored in the wallet's vault.

#### Parameters

| Name | Type |
| :------ | :------ |
| `query` | `QueryParameters` |

#### Returns

`Promise`<`$200`\>

#### Implementation of

[Wallet](../interfaces/Wallet.md).[resourceList](../interfaces/Wallet.md#resourcelist)

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:580](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L580)

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

[base-wallet/src/ts/wallet/base-wallet.ts:243](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L243)

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

[base-wallet/src/ts/wallet/base-wallet.ts:229](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L229)

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

[base-wallet/src/ts/wallet/base-wallet.ts:726](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L726)

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

[base-wallet/src/ts/wallet/base-wallet.ts:752](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L752)

___

### wipe

▸ **wipe**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Implementation of

Wallet.wipe

#### Defined in

[base-wallet/src/ts/wallet/base-wallet.ts:211](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/aadedf8/packages/base-wallet/src/ts/wallet/base-wallet.ts#L211)
