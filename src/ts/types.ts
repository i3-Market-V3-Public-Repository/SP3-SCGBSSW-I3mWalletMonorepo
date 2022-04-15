import { ContractInterface } from '@ethersproject/contracts'
import { JWEHeaderParameters, JWK as JWKjose, JWTHeaderParameters } from 'jose'
import { ENC_ALGS, HASH_ALGS, SIGNING_ALGS } from './constants'

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
}

export interface StoredProof<T extends NrProofPayload> {
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
  timestamp: 'iat' | number
  notBefore: 'iat' | number // timestamp in ms
  notAfter: 'iat' | number // ms
  tolerance?: number // ms
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
}

export interface NrProofPayload extends ProofPayload {
  exchange: DataExchange
}

export interface PoOPayload extends NrProofPayload {
  iss: 'orig'
  proofType: 'PoO'
}

export interface PoRPayload extends NrProofPayload {
  iss: 'dest'
  proofType: 'PoR'
  poo: string // the received PoR as compact JWS
}

export interface PoPPayload extends NrProofPayload {
  iss: 'orig'
  proofType: 'PoP'
  por: string // the received PoR as compact JWS
  secret: string // Compact JWK of the secret to decrypt the ciphertext
  verificationCode: string // A string that can be used to check the publication of the secret in a reliable ledger. Current implementation is the tx hash (which can be used to look up the transaction in the ledger)
}

export interface ConflictResolutionRequestPayload extends ProofPayload {
  proofType: 'request'
  iss: 'orig' | 'dest'
  iat: number // unix timestamp for issued at
  por: string // a compact JWS holding a PoR. The proof MUST be signed with the same key as either 'orig' or 'dest' of the payload proof.
  dataExchangeId: string // the unique id of this data exchange
}

export interface VerificationRequestPayload extends ConflictResolutionRequestPayload {
  type: 'verificationRequest'
}

export interface DisputeRequestPayload extends ConflictResolutionRequestPayload {
  type: 'disputeRequest'
  iss: 'dest'
  cipherblock: string // the cipherblock as a JWE string
}

export interface ResolutionPayload extends ProofPayload {
  proofType: 'resolution'
  type?: string
  resolution?: string
  dataExchangeId: string // the unique id of this data exchange
  iat: number // unix timestamp stating when it was resolved
  iss: string // the public key of the CRS in JWK
  sub: string // the public key (JWK) of the entity that requested a resolution
}

export interface VerificationResolutionPayload extends ResolutionPayload {
  type: 'verification'
  resolution: 'completed' | 'not completed' // whether the data exchange has been verified to be complete
}

export interface DisputeResolutionPayload extends ResolutionPayload {
  type: 'dispute'
  resolution: 'accepted' | 'denied' // resolution is 'denied' if the cipherblock can be properly decrypted; otherwise is 'accepted'
}

export interface DecodedProof<T extends ProofPayload> {
  header: JWTHeaderParameters
  payload: T
  signer?: JWK // Public JWK used to verify the signature
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
'invalid timestamp' |
'invalid format' |
'cannot contact the ledger' |
'cannot verify'
