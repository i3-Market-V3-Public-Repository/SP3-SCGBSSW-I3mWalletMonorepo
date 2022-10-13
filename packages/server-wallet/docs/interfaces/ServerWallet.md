# Interface: ServerWallet

## Hierarchy

- `BokWallet`

  ↳ **`ServerWallet`**

## Table of contents

### Properties

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
- [providerinfo](ServerWallet.md#providerinfo)
- [queryBalance](ServerWallet.md#querybalance)
- [resourceCreate](ServerWallet.md#resourcecreate)
- [resourceList](ServerWallet.md#resourcelist)
- [selectCredentialsForSdr](ServerWallet.md#selectcredentialsforsdr)
- [selectIdentity](ServerWallet.md#selectidentity)
- [selectiveDisclosure](ServerWallet.md#selectivedisclosure)
- [transactionDeploy](ServerWallet.md#transactiondeploy)
- [wipe](ServerWallet.md#wipe)

## Properties

### dialog

• **dialog**: `NullDialog`

#### Overrides

BokWallet.dialog

#### Defined in

[server-wallet/src/ts/index.ts:10](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/server-wallet/src/ts/index.ts#L10)

___

### keyWallet

• `Protected` **keyWallet**: `KeyWallet`<`Uint8Array`\>

#### Inherited from

BokWallet.keyWallet

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L22)

___

### provider

• `Protected` **provider**: `string`

#### Inherited from

BokWallet.provider

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:24](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L24)

___

### providersData

• `Protected` **providersData**: `Record`<`string`, `ProviderData`\>

#### Inherited from

BokWallet.providersData

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:25](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L25)

___

### resourceValidator

• `Protected` **resourceValidator**: `ResourceValidator`

#### Inherited from

BokWallet.resourceValidator

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:23](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L23)

___

### store

• **store**: `FileStore`

#### Overrides

BokWallet.store

#### Defined in

[server-wallet/src/ts/index.ts:11](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/server-wallet/src/ts/index.ts#L11)

___

### toast

• **toast**: `ConsoleToast`

#### Overrides

BokWallet.toast

#### Defined in

[server-wallet/src/ts/index.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/server-wallet/src/ts/index.ts#L12)

___

### veramo

• **veramo**: `default`<`BaseWalletModel`\>

#### Inherited from

BokWallet.veramo

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:21](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L21)

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

[base-wallet/types/wallet/base-wallet.d.ts:34](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L34)

___

### createTransaction

▸ **createTransaction**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Inherited from

BokWallet.createTransaction

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:29](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L29)

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

#### Inherited from

BokWallet.deleteIdentity

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:88](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L88)

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

#### Inherited from

BokWallet.deleteResource

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:83](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L83)

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

#### Inherited from

BokWallet.didJwtVerify

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:117](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L117)

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

[base-wallet/types/wallet/base-wallet.d.ts:27](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L27)

___

### getIdentities

▸ **getIdentities**(): `Promise`<{ `[did: string]`: `Identity`;  }\>

Gets a list of identities managed by this wallet

#### Returns

`Promise`<{ `[did: string]`: `Identity`;  }\>

#### Inherited from

BokWallet.getIdentities

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:39](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L39)

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

[base-wallet/types/wallet/base-wallet.d.ts:33](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L33)

___

### getResources

▸ **getResources**(): `Promise`<{ `[id: string]`: `Resource`;  }\>

Gets a resource securey stored in the wallet's vaulr. It is the place where to find stored verfiable credentials.

#### Returns

`Promise`<{ `[id: string]`: `Resource`;  }\>

#### Inherited from

BokWallet.getResources

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:73](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L73)

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

#### Inherited from

BokWallet.identityCreate

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:52](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L52)

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

[base-wallet/types/wallet/base-wallet.d.ts:68](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L68)

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

#### Inherited from

BokWallet.identityInfo

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:67](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L67)

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

#### Inherited from

BokWallet.identityList

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:46](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L46)

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

[base-wallet/types/wallet/base-wallet.d.ts:53](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L53)

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

#### Inherited from

BokWallet.identitySign

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:60](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L60)

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

[bok-wallet/types/bok-wallet.d.ts:8](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/bok-wallet/types/bok-wallet.d.ts#L8)

___

### providerinfo

▸ **providerinfo**(): `Promise`<`ProviderData`\>

Retrieves information regarding the current connection to the DLT.

#### Returns

`Promise`<`ProviderData`\>

#### Inherited from

BokWallet.providerinfo

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:122](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L122)

___

### queryBalance

▸ **queryBalance**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Inherited from

BokWallet.queryBalance

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:28](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L28)

___

### resourceCreate

▸ **resourceCreate**(`requestBody`): `Promise`<`ResourceId`\>

Securely stores in the wallet a new resource. Currently only supporting verifiable credentials, which are properly verified before storing them.

#### Parameters

| Name | Type |
| :------ | :------ |
| `requestBody` | `VerifiableCredential` |

#### Returns

`Promise`<`ResourceId`\>

and identifier of the created resource

#### Inherited from

BokWallet.resourceCreate

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:95](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L95)

___

### resourceList

▸ **resourceList**(): `Promise`<`ResourceListOutput`\>

Gets a list of resources (currently just verifiable credentials) stored in the wallet's vault.

#### Returns

`Promise`<`ResourceListOutput`\>

#### Inherited from

BokWallet.resourceList

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:78](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L78)

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

[base-wallet/types/wallet/base-wallet.d.ts:32](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L32)

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

[base-wallet/types/wallet/base-wallet.d.ts:31](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L31)

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

BokWallet.selectiveDisclosure

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:101](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L101)

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

BokWallet.transactionDeploy

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:107](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L107)

___

### wipe

▸ **wipe**(): `Promise`<`void`\>

#### Returns

`Promise`<`void`\>

#### Inherited from

BokWallet.wipe

#### Defined in

[base-wallet/types/wallet/base-wallet.d.ts:30](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/7a4bb44/packages/base-wallet/types/wallet/base-wallet.d.ts#L30)
