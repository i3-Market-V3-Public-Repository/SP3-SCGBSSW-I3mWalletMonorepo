import { exportJWK } from 'jose'
import { importJwk } from '../crypto'
import { NrError } from '../errors'
import { JWK } from '../types'
import { jsonSort } from './jsonSort'

export async function parseJwk (jwk: JWK, stringify: boolean = true): Promise<string> {
  try {
    const key = await importJwk(jwk, jwk.alg)
    const jwk2 = await exportJWK(key)
    jwk2.alg = jwk.alg
    const sortedJwk = jsonSort(jwk2)
    return (stringify) ? JSON.stringify(sortedJwk) : sortedJwk
  } catch (error) {
    throw new NrError(error, ['invalid key'])
  }
}
