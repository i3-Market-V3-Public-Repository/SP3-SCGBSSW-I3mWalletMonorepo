import { SignJWT } from 'jose'
import { JWK, NrProofPayload, StoredProof, DataExchange, Dict } from '../types'
import { verifyKeyPair } from '../crypto/verifyKeyPair'
import { importJwk } from '../crypto'

/**
 * Creates a non-repudiable proof for a given data exchange
 * @param payload - the payload to be added to the proof.
 *                  `payload.iss` must be either the origin 'orig' or the destination 'dest' of the data exchange
 *                  `payload.iat` shall be ommitted since it will be automatically added when signing (`Date.now()`)
 * @param privateJwk - The private key in JWK that will sign the proof
 * @returns a proof as a compact JWS formatted JWT string
 */
export async function createProof<T extends NrProofPayload> (payload: Omit<T, 'iat'>, privateJwk: JWK): Promise<StoredProof<T>> {
  if (payload.iss === undefined) {
    throw new Error('Payload iss should be set to either "orig" or "dest"')
  }

  // Check that that the privateKey is the complement to the public key of the issuer
  const publicJwk = JSON.parse((payload.exchange as Dict<DataExchange>)[payload.iss] as string) as JWK

  await verifyKeyPair(publicJwk, privateJwk) // if verification fails it throws an error and the following is not executed

  const privateKey = await importJwk(privateJwk)

  const alg = privateJwk.alg as string // if alg were undefined verifyKeyPair would have thrown an error

  const proofPayload = {
    ...payload,
    iat: Math.floor(Date.now() / 1000)
  }

  const jws = await new SignJWT(proofPayload)
    .setProtectedHeader({ alg })
    .setIssuedAt(proofPayload.iat)
    .sign(privateKey)

  return {
    jws,
    payload: proofPayload as T
  }
}
