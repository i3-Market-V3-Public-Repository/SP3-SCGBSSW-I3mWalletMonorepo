import { WalletProtocol, ProtocolPKEData, AuthData, PKEData, ProtocolAuthData } from '../internal'

export interface Transport {
  prepare: (protocol: WalletProtocol, publicKey: string) => Promise<PKEData>
  publicKeyExchange: (protocol: WalletProtocol, pkeData: PKEData) => Promise<ProtocolPKEData>
  authentication: (protocol: WalletProtocol, authData: AuthData) => Promise<ProtocolAuthData>
  finish: () => void
}

export abstract class BaseTransport implements Transport {
  abstract prepare (protocol: WalletProtocol, publicKey: string): Promise<PKEData>

  abstract publicKeyExchange (protocol: WalletProtocol, publicKey: PKEData): Promise<ProtocolPKEData>
  abstract authentication (protocol: WalletProtocol, authData: AuthData): Promise<ProtocolAuthData>

  finish (): void {}
}
