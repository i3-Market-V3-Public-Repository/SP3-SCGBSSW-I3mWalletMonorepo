import * as b64 from '@juanelas/base64'
import { JWTHeaderParameters, jwtVerify } from 'jose'
import { NrError } from '../errors/index.js'
import { DecodedProof, getFromJws, JWK, ProofPayload } from '../types.js'
import { importJwk } from './importJwk.js'

/**
 * Decodes and optionally verifies a JWS, and returns the decoded header, payload.
 * @param jws
 * @param publicJwk - either a public key as a JWK or a function that resolves to a JWK. If not provided, the JWS signature is not verified
 */
export async function jwsDecode<T extends ProofPayload> (jws: string, publicJwk?: JWK | getFromJws<T>): Promise<DecodedProof<T>> {
  const regex = /^([a-zA-Z0-9_-]+)\.{1,2}([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/
  const match = jws.match(regex)

  if (match === null) {
    throw new NrError(new Error(`${jws} is not a JWS`), ['not a compact jws'])
  }

  let header: JWTHeaderParameters
  let payload: T
  try {
    header = JSON.parse(b64.decode(match[1], true) as string)
    payload = JSON.parse(b64.decode(match[2], true) as string)
  } catch (error) {
    throw new NrError(error, ['invalid format', 'not a compact jws'])
  }

  if (publicJwk !== undefined) {
    const pubJwk = (typeof publicJwk === 'function') ? await publicJwk(header, payload) : publicJwk
    const pubKey = await importJwk(pubJwk)
    try {
      const verified = await jwtVerify(jws, pubKey)
      return {
        header: verified.protectedHeader,
        payload: verified.payload as unknown as T,
        signer: pubJwk
      }
    } catch (error) {
      throw new NrError(error, ['jws verification failed'])
    }
  }

  return { header, payload }
}
