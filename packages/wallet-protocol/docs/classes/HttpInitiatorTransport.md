# Class: HttpInitiatorTransport

## Hierarchy

- `InitiatorTransport`<[`HttpRequest`](../interfaces/HttpRequest.md), [`HttpResponse`](../interfaces/HttpResponse.md)\>

  ↳ **`HttpInitiatorTransport`**

## Table of contents

### Constructors

- [constructor](HttpInitiatorTransport.md#constructor)

### Properties

- [connString](HttpInitiatorTransport.md#connstring)
- [opts](HttpInitiatorTransport.md#opts)

### Methods

- [authentication](HttpInitiatorTransport.md#authentication)
- [baseSend](HttpInitiatorTransport.md#basesend)
- [finish](HttpInitiatorTransport.md#finish)
- [prepare](HttpInitiatorTransport.md#prepare)
- [publicKeyExchange](HttpInitiatorTransport.md#publickeyexchange)
- [send](HttpInitiatorTransport.md#send)
- [sendRequest](HttpInitiatorTransport.md#sendrequest)
- [verification](HttpInitiatorTransport.md#verification)

## Constructors

### constructor

• **new HttpInitiatorTransport**(`opts?`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `opts` | `Partial`<`InitiatorOptions`\> |

#### Inherited from

InitiatorTransport<HttpRequest, HttpResponse\>.constructor

#### Defined in

[src/ts/transport/initiator-transport.ts:31](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/wallet-protocol/src/ts/transport/initiator-transport.ts#L31)

## Properties

### connString

• **connString**: `undefined` \| [`ConnectionString`](ConnectionString.md)

#### Inherited from

InitiatorTransport.connString

#### Defined in

[src/ts/transport/initiator-transport.ts:29](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/wallet-protocol/src/ts/transport/initiator-transport.ts#L29)

___

### opts

• `Protected` **opts**: `InitiatorOptions`

#### Inherited from

InitiatorTransport.opts

#### Defined in

[src/ts/transport/initiator-transport.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/wallet-protocol/src/ts/transport/initiator-transport.ts#L26)

## Methods

### authentication

▸ **authentication**(`protocol`, `authData`): `Promise`<[`ProtocolAuthData`](../interfaces/ProtocolAuthData.md)\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `protocol` | [`WalletProtocol`](WalletProtocol.md)<[`Transport`](../interfaces/Transport.md)<`any`, `any`\>\> |
| `authData` | [`AuthData`](../interfaces/AuthData.md) |

#### Returns

`Promise`<[`ProtocolAuthData`](../interfaces/ProtocolAuthData.md)\>

#### Inherited from

InitiatorTransport.authentication

#### Defined in

[src/ts/transport/initiator-transport.ts:95](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/wallet-protocol/src/ts/transport/initiator-transport.ts#L95)

___

### baseSend

▸ **baseSend**(`port`, `httpReq`): `Promise`<[`HttpResponse`](../interfaces/HttpResponse.md)\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `port` | `number` |
| `httpReq` | `RequestInit` |

#### Returns

`Promise`<[`HttpResponse`](../interfaces/HttpResponse.md)\>

#### Defined in

[src/ts/transport/http/http-initiator.ts:25](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/wallet-protocol/src/ts/transport/http/http-initiator.ts#L25)

___

### finish

▸ **finish**(`protocol`): `void`

#### Parameters

| Name | Type |
| :------ | :------ |
| `protocol` | [`WalletProtocol`](WalletProtocol.md)<[`Transport`](../interfaces/Transport.md)<`any`, `any`\>\> |

#### Returns

`void`

#### Inherited from

InitiatorTransport.finish

#### Defined in

[src/ts/transport/initiator-transport.ts:134](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/wallet-protocol/src/ts/transport/initiator-transport.ts#L134)

___

### prepare

▸ **prepare**(`protocol`, `publicKey`): `Promise`<[`PKEData`](../interfaces/PKEData.md)\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `protocol` | [`WalletProtocol`](WalletProtocol.md)<[`Transport`](../interfaces/Transport.md)<`any`, `any`\>\> |
| `publicKey` | `string` |

#### Returns

`Promise`<[`PKEData`](../interfaces/PKEData.md)\>

#### Inherited from

InitiatorTransport.prepare

#### Defined in

[src/ts/transport/initiator-transport.ts:45](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/wallet-protocol/src/ts/transport/initiator-transport.ts#L45)

___

### publicKeyExchange

▸ **publicKeyExchange**(`protocol`, `pkeData`): `Promise`<[`ProtocolPKEData`](../interfaces/ProtocolPKEData.md)\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `protocol` | [`WalletProtocol`](WalletProtocol.md)<[`Transport`](../interfaces/Transport.md)<`any`, `any`\>\> |
| `pkeData` | [`PKEData`](../interfaces/PKEData.md) |

#### Returns

`Promise`<[`ProtocolPKEData`](../interfaces/ProtocolPKEData.md)\>

#### Inherited from

InitiatorTransport.publicKeyExchange

#### Defined in

[src/ts/transport/initiator-transport.ts:67](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/wallet-protocol/src/ts/transport/initiator-transport.ts#L67)

___

### send

▸ **send**(`masterKey`, `code`, `req`): `Promise`<[`HttpResponse`](../interfaces/HttpResponse.md)\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `masterKey` | [`MasterKey`](MasterKey.md) |
| `code` | `Uint8Array` |
| `req` | [`HttpRequest`](../interfaces/HttpRequest.md) |

#### Returns

`Promise`<[`HttpResponse`](../interfaces/HttpResponse.md)\>

#### Overrides

InitiatorTransport.send

#### Defined in

[src/ts/transport/http/http-initiator.ts:88](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/wallet-protocol/src/ts/transport/http/http-initiator.ts#L88)

___

### sendRequest

▸ **sendRequest**<`T`\>(`request`): `Promise`<`T`\>

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends `Request` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `request` | `Request` |

#### Returns

`Promise`<`T`\>

#### Overrides

InitiatorTransport.sendRequest

#### Defined in

[src/ts/transport/http/http-initiator.ts:70](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/wallet-protocol/src/ts/transport/http/http-initiator.ts#L70)

___

### verification

▸ **verification**(`protocol`, `masterKey`): `Promise`<`Uint8Array`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `protocol` | [`WalletProtocol`](WalletProtocol.md)<[`Transport`](../interfaces/Transport.md)<`any`, `any`\>\> |
| `masterKey` | [`MasterKey`](MasterKey.md) |

#### Returns

`Promise`<`Uint8Array`\>

#### Inherited from

InitiatorTransport.verification

#### Defined in

[src/ts/transport/initiator-transport.ts:124](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/wallet-protocol/src/ts/transport/initiator-transport.ts#L124)
