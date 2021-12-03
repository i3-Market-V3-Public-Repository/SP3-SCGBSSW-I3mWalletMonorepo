import { importJWK, JWK, jwtVerify, JWTVerifyResult } from 'jose'
import { hashable } from 'object-sha'
import { DataExchange, DataExchangeInit, DateTolerance, ProofPayload, ProofInputPayload } from './types'

export { JWK, JWTVerifyResult }

/**
 * Verify a proof
 * @param proof - a non-repudiable proof in Compact JWS formatted JWT string
 *
 * @param publicJwk - the publicKey as a JWK to use for verifying the signature. If MUST match either orig or dest (the one pointed on the iss field)
 *
 * @param expectedPayloadClaims - The expected values of the proof's payload claims. An example could be:
 * {
 *   proofType: 'PoO',
 *   iss: 'orig',
 *   exchange: {
 *     id: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
 *     orig: '{"kty":"EC","x":"rPMP39e-o8cU6m4WL8_qd2wxo-nBTjWXZtPGBiiGCTY","y":"0uvxGEebFDxKOHYUlHREzq4mRULuZvQ6LB2I11yE1E0","crv":"P-256"}', // Public key in JSON.stringify(JWK) of the block origin (sender)
 *     dest: '{"kty":"EC","x":"qf_mNdy57ia1vAq5QLpTPxJUCRhS2003-gL0nLcbXoA","y":"H_8YwSCKJhDbZv17YEgDfAiKTaQ8x0jpLYCC2myxAeY","crv":"P-256"}', // Public key in JSON.stringify(JWK) of the block destination (receiver)
 *     hash_alg: 'SHA-256',
 *     cipherblock_dgst: 'IBUIstf98_afbiuh7UaifkasytNih7as-Jah61ls9UI', // hash of the cipherblock in base64url with no padding
 *     block_commitment: 'iHAdgHDQVo6qaD0KqJ9ZMlVmVA3f3AI6uZG0jFqeu14', // hash of the plaintext block in base64url with no padding
 *     secret_commitment: 'svipVfsi6vsoj3Zk_6LWi3k6mMdQOSSY1OrHGnaM5eA' // hash of the secret that can be used to decrypt the block in base64url with no padding
 *   }
 * }
 *
 * @param dateTolerance - specifies a time window to accept the proof. An example could be
 * {
 *   currentDate: new Date('2021-10-17T03:24:00'), // Date to use when comparing NumericDate claims, defaults to new Date().
 *   clockTolerance: 10  // string|number Expected clock tolerance in seconds when number (e.g. 5), or parsed as seconds when a string (e.g. "5 seconds", "10 minutes", "2 hours")
 * }
 *
 * @returns The JWT protected header and payload if the proof is validated
 */
export async function verifyProof (proof: string, publicJwk: JWK, expectedPayloadClaims: ProofInputPayload, dateTolerance?: DateTolerance): Promise<JWTVerifyResult> {
  const pubKey = await importJWK(publicJwk)
  const verification = await jwtVerify(proof, pubKey, dateTolerance)
  const payload = verification.payload as ProofPayload

  // Check that that the publicKey is the public key of the issuer
  const issuer = payload.exchange[payload.iss]
  if (hashable(publicJwk) !== hashable(JSON.parse(issuer))) {
    throw new Error(`The proof is issued by ${issuer} instead of ${JSON.stringify(publicJwk)}`)
  }

  for (const key in expectedPayloadClaims) {
    if (payload[key] === undefined) throw new Error(`Expected key '${key}' not found in proof`)
    if (key === 'exchange') {
      const expectedDataExchange = expectedPayloadClaims.exchange
      const dataExchange = payload.exchange as DataExchange
      checkDataExchange(dataExchange, expectedDataExchange)
    } else {
      if (hashable(expectedPayloadClaims[key] as object) !== hashable(payload[key] as object)) {
        throw new Error(`Proof's ${key}: ${JSON.stringify(payload[key], undefined, 2)} does not meet provided value ${JSON.stringify(expectedPayloadClaims[key], undefined, 2)}`)
      }
    }
  }
  return (verification)
}

/**
 * Checks whether a dataExchange claims meet the expected ones
 */
function checkDataExchange (dataExchange: DataExchange, expectedDataExchange: DataExchangeInit): void {
  // First, let us check that the dataExchange is complete
  const claims: Array<keyof DataExchange> = ['id', 'orig', 'dest', 'hashAlg', 'cipherblockDgst', 'blockCommitment', 'blockCommitment', 'secretCommitment', 'schema']
  for (const claim of claims) {
    if (claim !== 'schema' && (dataExchange[claim] === undefined || dataExchange[claim] === '')) {
      throw new Error(`${claim} is missing on dataExchange.\ndataExchange: ${JSON.stringify(dataExchange, undefined, 2)}`)
    }
  }

  // And now let's check the expected values
  for (const key in expectedDataExchange) {
    if (hashable(expectedDataExchange[key as keyof DataExchangeInit] as unknown as object) !== hashable(dataExchange[key as keyof DataExchangeInit] as unknown as object)) {
      throw new Error(`dataExchange's ${key}: ${JSON.stringify(dataExchange[key as keyof DataExchange], undefined, 2)} does not meet expected value ${JSON.stringify(expectedDataExchange[key as keyof DataExchangeInit], undefined, 2)}`)
    }
  }
}
