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
| `opts` | `WalletOptions`<`BokWalletModel`\> |

#### Inherited from

BaseWallet<WalletOptions<BokWalletModel\>\>.constructor

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:27](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L27)

## Properties

### dialog

• **dialog**: `Dialog`

#### Inherited from

BaseWallet.dialog

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:19](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L19)

___

### keyWallet

• `Protected` **keyWallet**: `KeyWallet`<`Uint8Array`\>

#### Inherited from

BaseWallet.keyWallet

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:23](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L23)

___

### provider

• `Protected` **provider**: `string`

#### Inherited from

BaseWallet.provider

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:25](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L25)

___

### providersData

• `Protected` **providersData**: `Record`<`string`, `ProviderData`\>

#### Inherited from

BaseWallet.providersData

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L26)

___

### resourceValidator

• `Protected` **resourceValidator**: `ResourceValidator`

#### Inherited from

BaseWallet.resourceValidator

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:24](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L24)

___

### store

• **store**: `Store`<`BaseWalletModel`\>

#### Inherited from

BaseWallet.store

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:20](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L20)

___

### toast

• **toast**: `Toast`

#### Inherited from

BaseWallet.toast

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:21](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L21)

___

### veramo

• **veramo**: `default`<`BaseWalletModel`\>

#### Inherited from

BaseWallet.veramo

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L22)

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

[base-wallet/types/wallet/base-wallet.d.ts:35](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L35)

___

### createTransaction

▸ **createTransaction**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Inherited from

BaseWallet.createTransaction

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:30](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L30)

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

#### Inherited from

BaseWallet.deleteIdentity

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:91](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L91)

___

### deleteResource

▸ **deleteResource**(`id`, `requestConfirmation?`): `Promise`<`void`\>

Deletes a given resource and all its children

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

[base-wallet/types/wallet/base-wallet.d.ts:86](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L86)

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

#### Inherited from

BaseWallet.didJwtVerify

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:120](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L120)

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

[base-wallet/types/wallet/base-wallet.d.ts:28](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L28)

___

### getIdentities

▸ **getIdentities**(): `Promise`<{ `[did: string]`: `Identity`;  }\>

Gets a list of identities managed by this wallet

#### Returns

`Promise`<{ `[did: string]`: `Identity`;  }\>

#### Inherited from

BaseWallet.getIdentities

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:40](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L40)

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

[base-wallet/types/wallet/base-wallet.d.ts:34](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L34)

___

### getResources

▸ **getResources**(): `Promise`<{ `[id: string]`: `Resource`;  }\>

Get resources stored in the wallet's vault. It is the place where to find stored verfiable credentials, agreements, non-repudiable proofs.

#### Returns

`Promise`<{ `[id: string]`: `Resource`;  }\>

#### Inherited from

BaseWallet.getResources

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:74](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L74)

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

#### Inherited from

BaseWallet.identityCreate

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:53](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L53)

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

[base-wallet/types/wallet/base-wallet.d.ts:69](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L69)

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

#### Inherited from

BaseWallet.identityInfo

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:68](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L68)

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

#### Inherited from

BaseWallet.identityList

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:47](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L47)

___

### identitySelect

▸ **identitySelect**(`queryParameters`): `Promise`<`$200`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `queryParameters` | `QueryParameters` |

#### Returns

`Promise`<`$200`\>

#### Inherited from

BaseWallet.identitySelect

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:54](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L54)

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

#### Inherited from

BaseWallet.identitySign

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:61](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L61)

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

[bok-wallet/src/ts/bok-wallet.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/bok-wallet/src/ts/bok-wallet.ts#L12)

___

### providerinfoGet

▸ **providerinfoGet**(): `Promise`<`$200`\>

Retrieves information regarding the current connection to the DLT.

#### Returns

`Promise`<`$200`\>

#### Inherited from

BaseWallet.providerinfoGet

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:125](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L125)

___

### queryBalance

▸ **queryBalance**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Inherited from

BaseWallet.queryBalance

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:29](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L29)

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

#### Inherited from

BaseWallet.resourceCreate

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:98](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L98)

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

#### Inherited from

BaseWallet.resourceList

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:81](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L81)

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

[base-wallet/types/wallet/base-wallet.d.ts:33](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L33)

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

[base-wallet/types/wallet/base-wallet.d.ts:32](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L32)

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

#### Inherited from

BaseWallet.selectiveDisclosure

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:104](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L104)

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

#### Inherited from

BaseWallet.transactionDeploy

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:110](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L110)

___

### wipe

▸ **wipe**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Inherited from

BaseWallet.wipe

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:31](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/base-wallet/types/wallet/base-wallet.d.ts#L31)
