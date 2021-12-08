import { importJWK, SignJWT } from 'jose'
import { JWK, ProofInputPayload, ProofPayload, StoredProof } from './types'
import { verifyKeyPair } from './verifyKeyPair'

/**
 * Creates a non-repudiable proof for a given data exchange
 * @param payload - the payload to be added to the proof.
 *                  `payload.iss` must be either the origin 'orig' or the destination 'dest' of the data exchange
 *                  `payload.iat` shall be ommitted since it will be automatically added when signing (`Date.now()`)
 * @param privateJwk - The private key in JWK that will sign the proof
 * @returns a proof as a compact JWS formatted JWT string
 */
export async function createProof (payload: ProofInputPayload, privateJwk: JWK): Promise<StoredProof> {
  if (payload.iss === undefined) {
    throw new Error('Payload iss should be set to either "orig" or "dest"')
  }

  // Check that that the privateKey is the complement to the public key of the issuer
  const publicJwk = JSON.parse(payload.exchange[payload.iss]) as JWK

  await verifyKeyPair(publicJwk, privateJwk) // if verification fails it throws an error and the following is not executed

  const privateKey = await importJWK(privateJwk)

  const alg = privateJwk.alg as string // if alg were undefined verifyKeyPair would have thrown an error

  payload.iat = Math.floor(Date.now() / 1000)

  const jws = await new SignJWT(payload)
    .setProtectedHeader({ alg })
    .setIssuedAt(payload.iat)
    .sign(privateKey)

  return {
    jws,
    payload: payload as ProofPayload
  }
}
