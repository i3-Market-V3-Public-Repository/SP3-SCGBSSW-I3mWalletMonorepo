import { JWK, JWTPayload } from 'jose'

export interface Block {
  raw?: Uint8Array
  jwe?: string
  secret?: JWK
  poo?: string
  por?: string
  pop?: string
}

export interface DestBlock extends Block {
  jwe: string
}

export interface OrigBlock extends Block {
  raw: Uint8Array
}

export interface DateTolerance {
  clockTolerance: string | number // Date to use when comparing NumericDate claims,
  currentDate: Date // string|number Expected clock tolerance in seconds when number (e.g. 5), or parsed as seconds when a string (e.g. "5 seconds", "10 minutes", "2 hours")
}

export interface DataExchange {
  id: string // unique identifier of this exchange
  orig: string // Public key in JSON.stringify(JWK) of the block origin (sender)
  dest: string // Public key in JSON.stringify(JWK) of the block destination (receiver)
  hashAlg: string
  cipherblockDgst: string // hash of the cipherblock in base64url with no padding
  blockCommitment: string // hash of the plaintext block in base64url with no padding
  secretCommitment: string // hash of the secret that can be used to decrypt the block in base64url with no padding
  schema?: string // an optional schema. In the future it will be used to check the decrypted data
}

export interface DataExchangeInit {
  id: string // unique identifier of this exchange
  orig: string // Public key in JSON.stringify(JWK) of the block origin (sender)
  dest: string // Public key in JSON.stringify(JWK) of the block destination (receiver)
  hashAlg: string
  cipherblockDgst?: string // hash of the cipherblock in base64url with no padding
  blockCommitment?: string // hash of the plaintext block in base64url with no padding
  secretCommitment?: string // hash of the secret that can be used to decrypt the block in base64url with no padding
  schema?: string // an optional schema. In the future it will be used to check the decrypted data
}

export interface JwkPair {
  publicJwk: JWK
  privateJwk: JWK
}

interface ProofCommonPayload extends JWTPayload {
  exchange: DataExchangeInit
}

export interface PoOPayload extends ProofCommonPayload {
  iss: 'orig' // it points to 'orig' or 'dest' of the DataExchange
  proofType: 'PoO'
}

export interface PoRPayload extends ProofCommonPayload {
  iss: 'dest' // it points to 'orig' or 'dest' of the DataExchange
  proofType: 'PoR'
  pooDgst: string // hash of the received PoO in base64url with no padding base64url(hash(poo in compact JWT))
}

export interface PoPPayload extends ProofCommonPayload {
  iss: 'orig' // it points to 'orig' or 'dest' of the DataExchange
  proofType: 'PoP'
  porDgst: string // hash of the received PoR in base64url with no padding base64url(hash(poo in compact JWT))
  secret: string // Compact JWK of the secret to decrypt the ciphertext
  verificationCode: string // A string that can be used to check the publication of the secret in a reliable ledger (e.g. tx_id, block id)
}

export type ProofInputPayload = PoOPayload | PoRPayload | PoPPayload

export type ProofPayload = ProofInputPayload & { iat: number }
