import { hashable } from 'object-sha'
import { jwsDecode } from '../crypto/'
import { DataExchange, JwsHeaderAndPayload, ProofInputPayload, ProofPayload, TimestampVerifyOptions } from '../types'
import { checkIssuedAt } from '../utils/checkIssuedAt'

/**
 * Verify a proof
 * @param proof - a non-repudiable proof in Compact JWS formatted JWT string
 *
 * @param expectedPayloadClaims - The expected values of the proof's payload claims. An expected value of '' can be use to just check that the claim is in the payload. An example could be:
 * {
 *   proofType: 'PoO',
 *   iss: 'orig',
 *   exchange: {
 *     id: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
 *     orig: '{"kty":"EC","x":"rPMP39e-o8cU6m4WL8_qd2wxo-nBTjWXZtPGBiiGCTY","y":"0uvxGEebFDxKOHYUlHREzq4mRULuZvQ6LB2I11yE1E0","crv":"P-256"}', // Public key in JSON.stringify(JWK) of the block origin (sender)
 *     dest: '{"kty":"EC","x":"qf_mNdy57ia1vAq5QLpTPxJUCRhS2003-gL0nLcbXoA","y":"H_8YwSCKJhDbZv17YEgDfAiKTaQ8x0jpLYCC2myxAeY","crv":"P-256"}', // Public key in JSON.stringify(JWK) of the block destination (receiver)
 *     hash_alg: 'SHA-256',
 *     cipherblock_dgst: 'IBUIstf98_afbiuh7UaifkasytNih7as-Jah61ls9UI', // hash of the cipherblock in base64url with no padding
 *     block_commitment: '', // hash of the plaintext block in base64url with no padding
 *     secret_commitment: '' // hash of the secret that can be used to decrypt the block in base64url with no padding
 *   }
 * }
 *
 * @param timestampVerifyOptions - specifies a time window to accept the proof
 *
 * @returns The JWT protected header and payload if the proof is validated
 */
export async function verifyProof<T extends ProofPayload> (proof: string, expectedPayloadClaims: ProofInputPayload, timestampVerifyOptions?: TimestampVerifyOptions): Promise<JwsHeaderAndPayload<T>> {
  const publicJwk = JSON.parse((expectedPayloadClaims.exchange as any)[expectedPayloadClaims.iss] as string)

  const verification = await jwsDecode<T>(proof, publicJwk)

  if (verification.payload.iss === undefined) {
    throw new Error('Property "iss" missing')
  }
  if (verification.payload.iat === undefined) {
    throw new Error('Property claim iat missing')
  }

  checkIssuedAt(verification.payload.iat, timestampVerifyOptions)

  const payload = verification.payload

  // Check that the publicKey is the public key of the issuer
  const issuer = payload.exchange[payload.iss]
  if (hashable(publicJwk) !== hashable(JSON.parse(issuer))) {
    throw new Error(`The proof is issued by ${issuer} instead of ${JSON.stringify(publicJwk)}`)
  }

  for (const key in expectedPayloadClaims) {
    if (payload[key] === undefined) throw new Error(`Expected key '${key}' not found in proof`)
    if (key === 'exchange') {
      const expectedDataExchange = expectedPayloadClaims.exchange
      const dataExchange = payload.exchange
      checkDataExchange(dataExchange, expectedDataExchange)
    } else if (expectedPayloadClaims[key] !== '' && hashable(expectedPayloadClaims[key] as object) !== hashable(payload[key] as object)) {
      throw new Error(`Proof's ${key}: ${JSON.stringify(payload[key], undefined, 2)} does not meet provided value ${JSON.stringify(expectedPayloadClaims[key], undefined, 2)}`)
    }
  }
  return verification
}

/**
 * Checks whether a dataExchange claims meet the expected ones
 */
function checkDataExchange (dataExchange: DataExchange, expectedDataExchange: DataExchange): void {
  // First, let us check that the dataExchange is complete
  const claims: Array<keyof DataExchange> = ['id', 'orig', 'dest', 'hashAlg', 'cipherblockDgst', 'blockCommitment', 'blockCommitment', 'secretCommitment', 'schema']
  for (const claim of claims) {
    if (claim !== 'schema' && (dataExchange[claim] === undefined || dataExchange[claim] === '')) {
      throw new Error(`${claim} is missing on dataExchange.\ndataExchange: ${JSON.stringify(dataExchange, undefined, 2)}`)
    }
  }

  // And now let's check the expected values
  for (const key in expectedDataExchange) {
    if (expectedDataExchange[key as keyof DataExchange] !== '' && hashable(expectedDataExchange[key as keyof DataExchange] as unknown as object) !== hashable(dataExchange[key as keyof DataExchange] as unknown as object)) {
      throw new Error(`dataExchange's ${key}: ${JSON.stringify(dataExchange[key as keyof DataExchange], undefined, 2)} does not meet expected value ${JSON.stringify(expectedDataExchange[key as keyof DataExchange], undefined, 2)}`)
    }
  }
}
