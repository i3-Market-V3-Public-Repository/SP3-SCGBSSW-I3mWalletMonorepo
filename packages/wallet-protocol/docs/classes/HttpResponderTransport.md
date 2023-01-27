# Class: HttpResponderTransport

## Hierarchy

- `ResponderTransport`<`http.IncomingMessage`, `never`\>

  ↳ **`HttpResponderTransport`**

## Table of contents

### Constructors

- [constructor](HttpResponderTransport.md#constructor)

### Properties

- [connString](HttpResponderTransport.md#connstring)
- [lastPairing](HttpResponderTransport.md#lastpairing)
- [listeners](HttpResponderTransport.md#listeners)
- [opts](HttpResponderTransport.md#opts)
- [rpcSubject](HttpResponderTransport.md#rpcsubject)
- [rpcUrl](HttpResponderTransport.md#rpcurl)

### Accessors

- [isPairing](HttpResponderTransport.md#ispairing)
- [port](HttpResponderTransport.md#port)
- [timeout](HttpResponderTransport.md#timeout)

### Methods

- [authentication](HttpResponderTransport.md#authentication)
- [dispatchEncryptedMessage](HttpResponderTransport.md#dispatchencryptedmessage)
- [dispatchProtocolMessage](HttpResponderTransport.md#dispatchprotocolmessage)
- [dispatchRequest](HttpResponderTransport.md#dispatchrequest)
- [finish](HttpResponderTransport.md#finish)
- [pairing](HttpResponderTransport.md#pairing)
- [prepare](HttpResponderTransport.md#prepare)
- [publicKeyExchange](HttpResponderTransport.md#publickeyexchange)
- [readRequestBody](HttpResponderTransport.md#readrequestbody)
- [send](HttpResponderTransport.md#send)
- [stopPairing](HttpResponderTransport.md#stoppairing)
- [use](HttpResponderTransport.md#use)
- [verification](HttpResponderTransport.md#verification)
- [waitRequest](HttpResponderTransport.md#waitrequest)

## Constructors

### constructor

• **new HttpResponderTransport**(`opts?`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `opts?` | `Partial`<[`HttpResponderOptions`](../interfaces/HttpResponderOptions.md)\> |

#### Overrides

ResponderTransport&lt;http.IncomingMessage, never\&gt;.constructor

#### Defined in

[transport/http/http-responder.ts:16](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/http/http-responder.ts#L16)

## Properties

### connString

• **connString**: `undefined` \| [`ConnectionString`](ConnectionString.md)

#### Inherited from

ResponderTransport.connString

#### Defined in

[transport/responder-transport.ts:40](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/responder-transport.ts#L40)

___

### lastPairing

• `Protected` **lastPairing**: `undefined` \| `Timeout`

#### Inherited from

ResponderTransport.lastPairing

#### Defined in

[transport/responder-transport.ts:37](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/responder-transport.ts#L37)

___

### listeners

• `Protected` **listeners**: `RequestListener`<typeof `IncomingMessage`, typeof `ServerResponse`\>[] = `[]`

#### Defined in

[transport/http/http-responder.ts:14](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/http/http-responder.ts#L14)

___

### opts

• `Protected` **opts**: `ResponderOptions`

#### Inherited from

ResponderTransport.opts

#### Defined in

[transport/responder-transport.ts:34](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/responder-transport.ts#L34)

___

### rpcSubject

• `Protected` **rpcSubject**: `Subject`<`SubjectData`<`Request`, `Request`\>\>

#### Inherited from

ResponderTransport.rpcSubject

#### Defined in

[transport/responder-transport.ts:35](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/responder-transport.ts#L35)

___

### rpcUrl

• `Readonly` **rpcUrl**: `string`

#### Defined in

[transport/http/http-responder.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/http/http-responder.ts#L13)

## Accessors

### isPairing

• `get` **isPairing**(): `boolean`

#### Returns

`boolean`

#### Inherited from

ResponderTransport.isPairing

#### Defined in

[transport/responder-transport.ts:71](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/responder-transport.ts#L71)

___

### port

• `get` **port**(): `number`

#### Returns

`number`

#### Inherited from

ResponderTransport.port

#### Defined in

[transport/responder-transport.ts:75](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/responder-transport.ts#L75)

___

### timeout

• `get` **timeout**(): `number`

#### Returns

`number`

#### Inherited from

ResponderTransport.timeout

#### Defined in

[transport/responder-transport.ts:79](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/responder-transport.ts#L79)

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

ResponderTransport.authentication

#### Defined in

[transport/responder-transport.ts:137](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/responder-transport.ts#L137)

___

### dispatchEncryptedMessage

▸ `Protected` **dispatchEncryptedMessage**(`req`, `res`, `authentication`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `req` | `IncomingMessage` |
| `res` | `ServerResponse`<`IncomingMessage`\> |
| `authentication` | `string` |

#### Returns

`Promise`<`void`\>

#### Defined in

[transport/http/http-responder.ts:40](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/http/http-responder.ts#L40)

___

### dispatchProtocolMessage

▸ `Protected` **dispatchProtocolMessage**(`req`, `res`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `req` | `IncomingMessage` |
| `res` | `ServerResponse`<`IncomingMessage`\> |

#### Returns

`Promise`<`void`\>

#### Defined in

[transport/http/http-responder.ts:30](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/http/http-responder.ts#L30)

___

### dispatchRequest

▸ **dispatchRequest**(`req`, `res`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `req` | `IncomingMessage` |
| `res` | `ServerResponse`<`IncomingMessage`\> |

#### Returns

`Promise`<`void`\>

#### Defined in

[transport/http/http-responder.ts:124](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/http/http-responder.ts#L124)

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

ResponderTransport.finish

#### Defined in

[transport/responder-transport.ts:179](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/responder-transport.ts#L179)

___

### pairing

▸ **pairing**(`protocol`, `port`, `timeout`): `Promise`<`void`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `protocol` | [`WalletProtocol`](WalletProtocol.md)<[`Transport`](../interfaces/Transport.md)<`any`, `any`\>\> |
| `port` | `number` |
| `timeout` | `number` |

#### Returns

`Promise`<`void`\>

#### Inherited from

ResponderTransport.pairing

#### Defined in

[transport/responder-transport.ts:54](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/responder-transport.ts#L54)

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

ResponderTransport.prepare

#### Defined in

[transport/responder-transport.ts:83](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/responder-transport.ts#L83)

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

ResponderTransport.publicKeyExchange

#### Defined in

[transport/responder-transport.ts:109](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/responder-transport.ts#L109)

___

### readRequestBody

▸ `Protected` **readRequestBody**(`req`): `Promise`<`string`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `req` | `IncomingMessage` |

#### Returns

`Promise`<`string`\>

#### Defined in

[transport/http/http-responder.ts:21](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/http/http-responder.ts#L21)

___

### send

▸ **send**(`masterKey`, `code`, `req`): `Promise`<`never`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `masterKey` | [`MasterKey`](MasterKey.md) |
| `code` | `Uint8Array` |
| `req` | `IncomingMessage` |

#### Returns

`Promise`<`never`\>

#### Inherited from

ResponderTransport.send

#### Defined in

[transport/transport.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/transport.ts#L22)

___

### stopPairing

▸ **stopPairing**(): `void`

#### Returns

`void`

#### Inherited from

ResponderTransport.stopPairing

#### Defined in

[transport/responder-transport.ts:64](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/responder-transport.ts#L64)

___

### use

▸ **use**(`listener`): `void`

#### Parameters

| Name | Type |
| :------ | :------ |
| `listener` | `RequestListener`<typeof `IncomingMessage`, typeof `ServerResponse`\> |

#### Returns

`void`

#### Defined in

[transport/http/http-responder.ts:145](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/http/http-responder.ts#L145)

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

ResponderTransport.verification

#### Defined in

[transport/responder-transport.ts:167](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/responder-transport.ts#L167)

___

### waitRequest

▸ **waitRequest**<`M`, `T`\>(`method`): `Promise`<`SubjectData`<`T`, `Request`\>\>

#### Type parameters

| Name | Type |
| :------ | :------ |
| `M` | extends ``"publicKeyExchange"`` \| ``"commitment"`` \| ``"nonce"`` \| ``"verification"`` \| ``"verificationChallenge"`` \| ``"acknowledgement"`` |
| `T` | extends `Object` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `method` | `M` |

#### Returns

`Promise`<`SubjectData`<`T`, `Request`\>\>

#### Inherited from

ResponderTransport.waitRequest

#### Defined in

[transport/responder-transport.ts:98](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/f97c6ca/packages/wallet-protocol/src/ts/transport/responder-transport.ts#L98)
