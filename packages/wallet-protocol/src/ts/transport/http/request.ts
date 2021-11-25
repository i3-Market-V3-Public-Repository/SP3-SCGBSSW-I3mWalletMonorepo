import { Identity } from '../../internal'

export interface PublicKeyExchangeRequest {
  method: 'publicKeyExchange'
  sender: Identity
  publicKey: string // hex string of the public key
  ra?: string // base64 random string
}

export interface CommitmentRequest {
  method: 'commitment'
  cx: string
}

export interface NonceRevealRequest {
  method: 'nonce'
  nx: string
}

export type Request = PublicKeyExchangeRequest | CommitmentRequest | NonceRevealRequest
