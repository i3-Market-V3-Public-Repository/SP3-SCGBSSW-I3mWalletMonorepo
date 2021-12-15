import { importJWK as importJWKjose } from 'jose'
import { NrError } from '../errors'
import { JWK, KeyLike } from '../types'

export async function importJwk (jwk: JWK, alg?: string): Promise<KeyLike | Uint8Array> {
  try {
    const key = await importJWKjose(jwk, alg)
    return key
  } catch (error) {
    throw new NrError(error, ['invalid key'])
  }
}
