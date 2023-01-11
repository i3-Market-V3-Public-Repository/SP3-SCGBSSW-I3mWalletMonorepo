# @i3m/wallet-protocol - v2.5.2

The implementation of a protocol that can securely connect the i3M Wallet with another application.

## Table of contents

### Classes

- [BaseTransport](classes/BaseTransport.md)
- [ConnectionString](classes/ConnectionString.md)
- [HttpInitiatorTransport](classes/HttpInitiatorTransport.md)
- [HttpResponderTransport](classes/HttpResponderTransport.md)
- [MasterKey](classes/MasterKey.md)
- [Session](classes/Session.md)
- [WalletProtocol](classes/WalletProtocol.md)

### Interfaces

- [AuthData](interfaces/AuthData.md)
- [CodeGenerator](interfaces/CodeGenerator.md)
- [HttpRequest](interfaces/HttpRequest.md)
- [HttpResponderOptions](interfaces/HttpResponderOptions.md)
- [HttpResponse](interfaces/HttpResponse.md)
- [Identity](interfaces/Identity.md)
- [PKEData](interfaces/PKEData.md)
- [ProtocolAuthData](interfaces/ProtocolAuthData.md)
- [ProtocolPKEData](interfaces/ProtocolPKEData.md)
- [Transport](interfaces/Transport.md)

### Type Aliases

- [TransportRequest](API.md#transportrequest)
- [TransportResponse](API.md#transportresponse)

### Variables

- [constants](API.md#constants)
- [defaultCodeGenerator](API.md#defaultcodegenerator)

## Type Aliases

### TransportRequest

Ƭ **TransportRequest**<`T`\>: `T` extends [`Transport`](interfaces/Transport.md)<infer Req\> ? `Req` : `never`

#### Type parameters

| Name |
| :------ |
| `T` |

#### Defined in

[transport/transport.ts:12](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/wallet-protocol/src/ts/transport/transport.ts#L12)

___

### TransportResponse

Ƭ **TransportResponse**<`T`\>: `T` extends [`Transport`](interfaces/Transport.md)<`any`, infer Res\> ? `Res` : `never`

#### Type parameters

| Name |
| :------ |
| `T` |

#### Defined in

[transport/transport.ts:13](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/wallet-protocol/src/ts/transport/transport.ts#L13)

## Variables

### constants

• **constants**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `COMMITMENT_LENGTH` | ``256`` |
| `DEFAULT_RANDOM_LENGTH` | ``36`` |
| `DEFAULT_TIMEOUT` | ``30000`` |
| `INITIAL_PORT` | ``29170`` |
| `NONCE_LENGTH` | ``128`` |
| `PORT_LENGTH` | ``12`` |
| `PORT_SPACE` | `number` |
| `RPC_URL_PATH` | ``".well-known/wallet-protocol"`` |

#### Defined in

[constants/index.ts:4](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/wallet-protocol/src/ts/constants/index.ts#L4)

___

### defaultCodeGenerator

• `Const` **defaultCodeGenerator**: [`CodeGenerator`](interfaces/CodeGenerator.md)

#### Defined in

[protocol/code-generator.ts:9](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/4ec1f56/packages/wallet-protocol/src/ts/protocol/code-generator.ts#L9)
