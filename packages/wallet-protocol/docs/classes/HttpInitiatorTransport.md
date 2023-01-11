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

[transport/initiator-transport.ts:30](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/48e30e2/packages/wallet-protocol/src/ts/transport/initiator-transport.ts#L30)

## Properties

### connString

• **connString**: `undefined` \| [`ConnectionString`](ConnectionString.md)

#### Inherited from

InitiatorTransport.connString

#### Defined in

[transport/initiator-transport.ts:28](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/48e30e2/packages/wallet-protocol/src/ts/transport/initiator-transport.ts#L28)

___

### opts

• `Protected` **opts**: `InitiatorOptions`

#### Inherited from

InitiatorTransport.opts

#### Defined in

[transport/initiator-transport.ts:25](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/48e30e2/packages/wallet-protocol/src/ts/transport/initiator-transport.ts#L25)

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

[transport/initiator-transport.ts:90](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/48e30e2/packages/wallet-protocol/src/ts/transport/initiator-transport.ts#L90)

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

[transport/http/http-initiator.ts:25](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/48e30e2/packages/wallet-protocol/src/ts/transport/http/http-initiator.ts#L25)

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

[transport/initiator-transport.ts:129](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/48e30e2/packages/wallet-protocol/src/ts/transport/initiator-transport.ts#L129)

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

[transport/initiator-transport.ts:44](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/48e30e2/packages/wallet-protocol/src/ts/transport/initiator-transport.ts#L44)

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

[transport/initiator-transport.ts:62](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/48e30e2/packages/wallet-protocol/src/ts/transport/initiator-transport.ts#L62)

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

[transport/http/http-initiator.ts:88](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/48e30e2/packages/wallet-protocol/src/ts/transport/http/http-initiator.ts#L88)

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

[transport/http/http-initiator.ts:70](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/48e30e2/packages/wallet-protocol/src/ts/transport/http/http-initiator.ts#L70)

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

[transport/initiator-transport.ts:119](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/48e30e2/packages/wallet-protocol/src/ts/transport/initiator-transport.ts#L119)
