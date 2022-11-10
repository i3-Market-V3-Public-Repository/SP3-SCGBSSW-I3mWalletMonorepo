import { importJWK as importJWKjose } from 'jose'
import { ENC_ALGS, SIGNING_ALGS } from '../constants'
import { NrError } from '../errors'
import { JWK, KeyLike } from '../types'

export async function importJwk (jwk: JWK, alg?: string): Promise<KeyLike | Uint8Array> {
  const jwkAlg = alg === undefined ? jwk.alg : alg
  const algs = (ENC_ALGS as unknown as string[]).concat(SIGNING_ALGS)
  if (!algs.includes(jwkAlg)) {
    throw new NrError('invalid alg. Must be one of: ' + algs.join(','), ['invalid algorithm'])
  }
  try {
    const key = await importJWKjose(jwk, alg)
    return key
  } catch (error) {
    throw new NrError(error, ['invalid key'])
  }
}
