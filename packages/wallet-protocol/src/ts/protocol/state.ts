
export interface Identity {
  name: string
  url?: string
}

export interface PKEData {
  id: Identity
  rx: Uint8Array
  publicKey: string
}

export interface ProtocolPKEData {
  a: PKEData
  b: PKEData

  sent: PKEData
  received: PKEData
}

export interface AuthData {
  cx: Uint8Array // commitment for the identity x
  nx: Uint8Array // nonce for the identity x
  r: Uint8Array
}

export interface ProtocolAuthData {
  a: AuthData
  b: AuthData

  sent: AuthData
  received: AuthData
}
