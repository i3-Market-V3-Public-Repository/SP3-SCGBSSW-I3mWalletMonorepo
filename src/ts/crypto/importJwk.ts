import { importJWK as importJWKjose } from 'jose'
import { ENC_ALGS, KEY_AGREEMENT_ALGS, SIGNING_ALGS } from '../constants.js'
import { NrError } from '../errors/index.js'
import { JWK, KeyLike } from '../types.js'

export async function importJwk (jwk: JWK, alg?: string): Promise<KeyLike | Uint8Array> {
  const jwkAlg = alg === undefined ? jwk.alg : alg
  const algs = (ENC_ALGS as unknown as string[]).concat(SIGNING_ALGS).concat(KEY_AGREEMENT_ALGS)
  if (!algs.includes(jwkAlg)) {
    throw new NrError('invalid alg. Must be one of: ' + algs.join(','), ['invalid algorithm'])
  }
  try {
    const key = await importJWKjose(jwk, alg)
    if (key === undefined || key === null) {
      throw new NrError(new Error('failed importing keys'), ['invalid key'])
    }
    return key
  } catch (error) {
    throw new NrError(error, ['invalid key'])
  }
}
