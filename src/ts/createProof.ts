import { importJWK, JWK, SignJWT } from 'jose'
import { ProofInputPayload } from './types'
import { verifyKeyPair } from './verifyKeyPair'

export { JWK }

/**
 * Creates a non-repudiable proof for a given data exchange
 * @param issuer - if the issuer of the proof is the origin 'orig' or the destination 'dest' of the data exchange
 * @param payload - the payload to be added to the proof.
 *                  `payload.iss` must be either the origin 'orig' or the destination 'dest' of the data exchange
 *                  `payload.iat` should be ommitted since it will be automatically added when signing (`Date.now()`)
 * @param privateJwk - The private key in JWK that will sign the proof
 * @returns a proof as a compact JWS formatted JWT string
 */
export async function createProof (payload: ProofInputPayload, privateJwk: JWK): Promise<string> {
  // Check that that the privateKey is the complement to the public key of the issuer
  const publicJwk = JSON.parse(payload.exchange[payload.iss]) as JWK

  await verifyKeyPair(publicJwk, privateJwk) // if verification fails it throws an error and the following is not executed

  const privateKey = await importJWK(privateJwk)

  const alg = privateJwk.alg as string // if alg wer undefined the previous import throws error

  return await new SignJWT(payload)
    .setProtectedHeader({ alg })
    .setIssuedAt()
    .sign(privateKey)
}
