# Interface: Transport<Req, Res\>

## Type parameters

| Name | Type |
| :------ | :------ |
| `Req` | `any` |
| `Res` | `any` |

## Implemented by

- [`BaseTransport`](../classes/BaseTransport.md)

## Table of contents

### Properties

- [authentication](Transport.md#authentication)
- [finish](Transport.md#finish)
- [prepare](Transport.md#prepare)
- [publicKeyExchange](Transport.md#publickeyexchange)
- [send](Transport.md#send)
- [verification](Transport.md#verification)

## Properties

### authentication

• **authentication**: (`protocol`: [`WalletProtocol`](../classes/WalletProtocol.md)<[`Transport`](Transport.md)<`any`, `any`\>\>, `authData`: [`AuthData`](AuthData.md)) => `Promise`<[`ProtocolAuthData`](ProtocolAuthData.md)\>

#### Type declaration

▸ (`protocol`, `authData`): `Promise`<[`ProtocolAuthData`](ProtocolAuthData.md)\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `protocol` | [`WalletProtocol`](../classes/WalletProtocol.md)<[`Transport`](Transport.md)<`any`, `any`\>\> |
| `authData` | [`AuthData`](AuthData.md) |

##### Returns

`Promise`<[`ProtocolAuthData`](ProtocolAuthData.md)\>

#### Defined in

[transport/transport.ts:6](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/742d14e/packages/wallet-protocol/src/ts/transport/transport.ts#L6)

___

### finish

• **finish**: (`protocol`: [`WalletProtocol`](../classes/WalletProtocol.md)<[`Transport`](Transport.md)<`any`, `any`\>\>) => `void`

#### Type declaration

▸ (`protocol`): `void`

##### Parameters

| Name | Type |
| :------ | :------ |
| `protocol` | [`WalletProtocol`](../classes/WalletProtocol.md)<[`Transport`](Transport.md)<`any`, `any`\>\> |

##### Returns

`void`

#### Defined in

[transport/transport.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/742d14e/packages/wallet-protocol/src/ts/transport/transport.ts#L9)

___

### prepare

• **prepare**: (`protocol`: [`WalletProtocol`](../classes/WalletProtocol.md)<[`Transport`](Transport.md)<`any`, `any`\>\>, `publicKey`: `string`) => `Promise`<[`PKEData`](PKEData.md)\>

#### Type declaration

▸ (`protocol`, `publicKey`): `Promise`<[`PKEData`](PKEData.md)\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `protocol` | [`WalletProtocol`](../classes/WalletProtocol.md)<[`Transport`](Transport.md)<`any`, `any`\>\> |
| `publicKey` | `string` |

##### Returns

`Promise`<[`PKEData`](PKEData.md)\>

#### Defined in

[transport/transport.ts:4](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/742d14e/packages/wallet-protocol/src/ts/transport/transport.ts#L4)

___

### publicKeyExchange

• **publicKeyExchange**: (`protocol`: [`WalletProtocol`](../classes/WalletProtocol.md)<[`Transport`](Transport.md)<`any`, `any`\>\>, `pkeData`: [`PKEData`](PKEData.md)) => `Promise`<[`ProtocolPKEData`](ProtocolPKEData.md)\>

#### Type declaration

▸ (`protocol`, `pkeData`): `Promise`<[`ProtocolPKEData`](ProtocolPKEData.md)\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `protocol` | [`WalletProtocol`](../classes/WalletProtocol.md)<[`Transport`](Transport.md)<`any`, `any`\>\> |
| `pkeData` | [`PKEData`](PKEData.md) |

##### Returns

`Promise`<[`ProtocolPKEData`](ProtocolPKEData.md)\>

#### Defined in

[transport/transport.ts:5](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/742d14e/packages/wallet-protocol/src/ts/transport/transport.ts#L5)

___

### send

• **send**: (`masterKey`: [`MasterKey`](../classes/MasterKey.md), `code`: `Uint8Array`, `request`: `Req`) => `Promise`<`Res`\>

#### Type declaration

▸ (`masterKey`, `code`, `request`): `Promise`<`Res`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `masterKey` | [`MasterKey`](../classes/MasterKey.md) |
| `code` | `Uint8Array` |
| `request` | `Req` |

##### Returns

`Promise`<`Res`\>

#### Defined in

[transport/transport.ts:8](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/742d14e/packages/wallet-protocol/src/ts/transport/transport.ts#L8)

___

### verification

• **verification**: (`protocol`: [`WalletProtocol`](../classes/WalletProtocol.md)<[`Transport`](Transport.md)<`any`, `any`\>\>, `masterKey`: [`MasterKey`](../classes/MasterKey.md)) => `Promise`<`Uint8Array`\>

#### Type declaration

▸ (`protocol`, `masterKey`): `Promise`<`Uint8Array`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `protocol` | [`WalletProtocol`](../classes/WalletProtocol.md)<[`Transport`](Transport.md)<`any`, `any`\>\> |
| `masterKey` | [`MasterKey`](../classes/MasterKey.md) |

##### Returns

`Promise`<`Uint8Array`\>

#### Defined in

[transport/transport.ts:7](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/742d14e/packages/wallet-protocol/src/ts/transport/transport.ts#L7)
