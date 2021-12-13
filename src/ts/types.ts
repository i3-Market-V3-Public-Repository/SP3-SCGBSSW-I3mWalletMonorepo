import { ContractInterface } from '@ethersproject/contracts'
import { JWK as JWKjose } from 'jose'

export { ContractInterface }
export { CompactDecryptResult, JWTVerifyResult } from 'jose'

export type HashAlg = 'SHA-256' | 'SHA-384' | 'SHA-512'
export type SigningAlg = 'ES256' | 'ES384' | 'ES512' // ECDSA with secp256k1 (ES256K) Edwards Curve DSA are not supported in browsers
export type EncryptionAlg = 'A128GCM' | 'A256GCM' // A192GCM is not supported in browsers

export interface Algs {
  hashAlg?: HashAlg
  SigningAlg?: SigningAlg
  EncAlg?: EncryptionAlg
}

export interface JWK extends JWKjose {
  alg: SigningAlg | EncryptionAlg
}

export interface ContractConfig {
  address: string
  abi: ContractInterface
}

export interface DltConfig {
  rpcProviderUrl: string // http://<host>:<port>
  gasLimit: number
  contract: ContractConfig
  disable: boolean
}

export interface StoredProof {
  jws: string
  payload: ProofPayload
}

export interface Block {
  raw?: Uint8Array
  jwe?: string
  secret?: {
    jwk: JWK
    hex: string
  }
  poo?: StoredProof
  por?: StoredProof
  pop?: StoredProof
}

export interface OrigBlock extends Block {
  raw: Uint8Array
  jwe: string
  secret: {
    jwk: JWK
    hex: string
  }
}

export interface TimestampVerifyOptions {
  currentTimestamp?: number // Unix timestamp in ms to use as current date when comparing dates. Defaults to (new Date()).valueOf()
  expectedTimestampInterval?: {
    min: number
    max: number
  }
  clockToleranceMs?: number // clock tolerance in milliseconds
}

export interface DataExchangeAgreement {
  [key: string]: string | number | undefined
  orig: string // Public key in JSON.stringify(JWK) of the block origin (sender)
  dest: string // Public key in JSON.stringify(JWK) of the block destination (receiver)
  hashAlg: HashAlg
  encAlg: EncryptionAlg
  signingAlg: SigningAlg
  ledgerContractAddress: string // contract address
  ledgerSignerAddress: string // address of the orig in the ledger
  pooToPorDelay: number // max milliseconds between issued PoO and verified PoR
  pooToPopDelay: number // max milliseconds between issued PoO and issued PoP
  pooToSecretDelay: number // max milliseconds between issued PoO and secret published on the ledger
  schema?: string // an optional schema. In the future it will be used to check the decrypted data
}

export interface DataExchange extends DataExchangeAgreement {
  id: string // base64url-no-padding encoded uint256 of the sha256(hashable(dataExchangeAgreement, cipherblockDgst))
  cipherblockDgst: string // hash of the cipherblock in base64url with no padding
  blockCommitment?: string // hash of the plaintext block in base64url with no padding
  secretCommitment?: string // hash of the secret that can be used to decrypt the block in base64url with no padding
}

export interface JwkPair {
  publicJwk: JWK
  privateJwk: JWK
}

export interface ProofInputPayload {
  [key: string]: string | number | DataExchange | undefined
  exchange: DataExchange
  iat?: number
  iss?: 'orig' | 'dest'
  proofType: string
  poo?: string
  por?: string
  secret?: string
  verificationCode?: string
}

export interface ProofPayload extends ProofInputPayload {
  iat: number
  iss: 'orig' | 'dest'
}

export interface PoOInputPayload extends ProofInputPayload {
  iss: 'orig' // it points to 'orig' or 'dest' of the DataExchange
  proofType: 'PoO'
}
export interface PoOPayload extends PoOInputPayload {
  iat: number
}

export interface PoRInputPayload extends ProofInputPayload {
  iss: 'dest' // it points to 'orig' or 'dest' of the DataExchange
  proofType: 'PoR'
  poo: string // // the received PoR as compact JWS
}
export interface PoRPayload extends PoRInputPayload {
  iat: number
}

export interface PoPInputPayload extends ProofInputPayload {
  iss: 'orig' // it points to 'orig' or 'dest' of the DataExchange
  proofType: 'PoP'
  por: string // the received PoR as compact JWS
  secret: string // Compact JWK of the secret to decrypt the ciphertext
}
export interface PoPPayload extends PoPInputPayload {
  iat: number
  verificationCode: string // A string that can be used to check the publication of the secret in a reliable ledger. Current implementation is the tx hash (which can be used to look up the transaction in the ledger)
}

interface ConflictResolutionRequest {
  [key: string]: string | number
  iss: 'orig' | 'dest'
  iat: number // unix timestamp for issued at
  por: string // a compact JWS holding a PoR. The proof MUST be signed with the same key as either 'orig' or 'dest' of the payload proof.
}

export interface VerificationRequestPayload extends ConflictResolutionRequest {
  type: 'verificationRequest'
}

export interface DisputeRequestPayload extends ConflictResolutionRequest {
  type: 'disputeRequest'
  iss: 'dest'
  cipherblock: string // the cipherblock as a JWE string
}
