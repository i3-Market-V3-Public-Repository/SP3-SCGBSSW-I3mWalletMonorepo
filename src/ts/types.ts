import { ContractInterface } from '@ethersproject/contracts'
import { JWEHeaderParameters, JWK as JWKjose, JWTHeaderParameters, JWTPayload } from 'jose'
import { DltSigner } from './signers'
import { HASH_ALGS, SIGNING_ALGS, ENC_ALGS } from './constants'

export { KeyLike } from 'jose'
export { ContractInterface }

export type HashAlg = typeof HASH_ALGS[number]
export type SigningAlg = typeof SIGNING_ALGS[number]
export type EncryptionAlg = typeof ENC_ALGS[number]

export type Dict<T> = T & {
  [key: string | symbol | number]: any | undefined
}

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
  signer?: DltSigner
}

export interface StoredProof<T extends ProofPayload> {
  jws: string
  payload: T
}

export interface Block {
  raw?: Uint8Array
  jwe?: string
  secret?: {
    jwk: JWK
    hex: string
  }
  poo?: StoredProof<PoOPayload>
  por?: StoredProof<PoRPayload>
  pop?: StoredProof<PoPPayload>
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
  id: string // base64url-no-padding encoded uint256 of the sha256(hashable(dataExchangeButId))
  cipherblockDgst: string // hash of the cipherblock in base64url with no padding
  blockCommitment: string // hash of the plaintext block in base64url with no padding
  secretCommitment: string // hash of the secret that can be used to decrypt the block in base64url with no padding
}

export interface JwkPair {
  publicJwk: JWK
  privateJwk: JWK
}

export interface ProofPayload {
  iat: number
  iss: string
  proofType: string
  exchange: DataExchange
}

export interface PoOPayload extends ProofPayload {
  iss: 'orig'
  proofType: 'PoO'
}

export interface PoRPayload extends ProofPayload {
  iss: 'dest'
  proofType: 'PoR'
  poo: string // the received PoR as compact JWS
}

export interface PoPPayload extends ProofPayload {
  iss: 'orig'
  proofType: 'PoP'
  por: string // the received PoR as compact JWS
  secret: string // Compact JWK of the secret to decrypt the ciphertext
  verificationCode: string // A string that can be used to check the publication of the secret in a reliable ledger. Current implementation is the tx hash (which can be used to look up the transaction in the ledger)
}

interface ConflictResolutionRequest extends JWTPayload {
  iss: 'orig' | 'dest'
  iat: number // unix timestamp for issued at
  por: string // a compact JWS holding a PoR. The proof MUST be signed with the same key as either 'orig' or 'dest' of the payload proof.
  dataExchangeId: string // the unique id of this data exchange
}

export interface VerificationRequestPayload extends ConflictResolutionRequest {
  type: 'verificationRequest'
}

export interface DisputeRequestPayload extends ConflictResolutionRequest {
  type: 'disputeRequest'
  iss: 'dest'
  cipherblock: string // the cipherblock as a JWE string
}

export interface Resolution extends JWTPayload {
  type?: string
  resolution?: string
  dataExchangeId: string // the unique id of this data exchange
  iat: number // unix timestamp stating when it was resolved
  iss: string // the public key of the CRS in JWK
}

export interface VerificationResolution extends Resolution {
  type: 'verification'
  resolution: 'completed' | 'not completed' // whether the data exchange has been verified to be complete
}

export interface DisputeResolution extends Resolution {
  type: 'dispute'
  resolution: 'accepted' | 'denied' // resolution is 'denied' if the cipherblock can be properly decrypted; otherwise is 'accepted'
}

export interface JwsHeaderAndPayload<T> {
  header: JWTHeaderParameters
  payload: T
}
export type getFromJws<T> = (header: JWEHeaderParameters, payload: T) => Promise<JWK>

export type NrErrorName =
'not a compact jws' |
'invalid key' |
'encryption failed' |
'decryption failed' |
'jws verification failed' |
'invalid algorithm' |
'invalid poo' |
'invalid por' |
'invalid pop' |
'invalid dispute request' |
'invalid verification request' |
'invalid dispute request' |
'data exchange not as expected' |
'dataExchange integrity violated' |
'secret not published' |
'secret not published in time' |
'received too late' |
'unexpected error' |
'invalid iat' |
'invalid format' |
'cannot contact the ledger' |
'cannot verify'
