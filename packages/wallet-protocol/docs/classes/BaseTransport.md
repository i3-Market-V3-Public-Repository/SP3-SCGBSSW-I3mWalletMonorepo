# Class: BaseTransport<Req, Res\>

## Type parameters

| Name |
| :------ |
| `Req` |
| `Res` |

## Implements

- [`Transport`](../interfaces/Transport.md)<`Req`, `Res`\>

## Table of contents

### Constructors

- [constructor](BaseTransport.md#constructor)

### Methods

- [authentication](BaseTransport.md#authentication)
- [finish](BaseTransport.md#finish)
- [prepare](BaseTransport.md#prepare)
- [publicKeyExchange](BaseTransport.md#publickeyexchange)
- [send](BaseTransport.md#send)
- [verification](BaseTransport.md#verification)

## Constructors

### constructor

• **new BaseTransport**<`Req`, `Res`\>()

#### Type parameters

| Name |
| :------ |
| `Req` |
| `Res` |

## Methods

### authentication

▸ `Abstract` **authentication**(`protocol`, `authData`): `Promise`<[`ProtocolAuthData`](../interfaces/ProtocolAuthData.md)\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `protocol` | [`WalletProtocol`](WalletProtocol.md)<[`Transport`](../interfaces/Transport.md)<`any`, `any`\>\> |
| `authData` | [`AuthData`](../interfaces/AuthData.md) |

#### Returns

`Promise`<[`ProtocolAuthData`](../interfaces/ProtocolAuthData.md)\>

#### Implementation of

Transport.authentication

#### Defined in

[src/ts/transport/transport.ts:19](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/wallet-protocol/src/ts/transport/transport.ts#L19)

___

### finish

▸ **finish**(`protocol`): `void`

#### Parameters

| Name | Type |
| :------ | :------ |
| `protocol` | [`WalletProtocol`](WalletProtocol.md)<[`Transport`](../interfaces/Transport.md)<`any`, `any`\>\> |

#### Returns

`void`

#### Implementation of

Transport.finish

#### Defined in

[src/ts/transport/transport.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/wallet-protocol/src/ts/transport/transport.ts#L26)

___

### prepare

▸ `Abstract` **prepare**(`protocol`, `publicKey`): `Promise`<[`PKEData`](../interfaces/PKEData.md)\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `protocol` | [`WalletProtocol`](WalletProtocol.md)<[`Transport`](../interfaces/Transport.md)<`any`, `any`\>\> |
| `publicKey` | `string` |

#### Returns

`Promise`<[`PKEData`](../interfaces/PKEData.md)\>

#### Implementation of

Transport.prepare

#### Defined in

[src/ts/transport/transport.ts:16](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/wallet-protocol/src/ts/transport/transport.ts#L16)

___

### publicKeyExchange

▸ `Abstract` **publicKeyExchange**(`protocol`, `publicKey`): `Promise`<[`ProtocolPKEData`](../interfaces/ProtocolPKEData.md)\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `protocol` | [`WalletProtocol`](WalletProtocol.md)<[`Transport`](../interfaces/Transport.md)<`any`, `any`\>\> |
| `publicKey` | [`PKEData`](../interfaces/PKEData.md) |

#### Returns

`Promise`<[`ProtocolPKEData`](../interfaces/ProtocolPKEData.md)\>

#### Implementation of

Transport.publicKeyExchange

#### Defined in

[src/ts/transport/transport.ts:18](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/wallet-protocol/src/ts/transport/transport.ts#L18)

___

### send

▸ **send**(`masterKey`, `code`, `req`): `Promise`<`Res`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `masterKey` | [`MasterKey`](MasterKey.md) |
| `code` | `Uint8Array` |
| `req` | `Req` |

#### Returns

`Promise`<`Res`\>

#### Implementation of

Transport.send

#### Defined in

[src/ts/transport/transport.ts:22](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/wallet-protocol/src/ts/transport/transport.ts#L22)

___

### verification

▸ `Abstract` **verification**(`protocol`, `masterKey`): `Promise`<`Uint8Array`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `protocol` | [`WalletProtocol`](WalletProtocol.md)<[`Transport`](../interfaces/Transport.md)<`any`, `any`\>\> |
| `masterKey` | [`MasterKey`](MasterKey.md) |

#### Returns

`Promise`<`Uint8Array`\>

#### Implementation of

Transport.verification

#### Defined in

[src/ts/transport/transport.ts:20](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/21cbec3/packages/wallet-protocol/src/ts/transport/transport.ts#L20)
