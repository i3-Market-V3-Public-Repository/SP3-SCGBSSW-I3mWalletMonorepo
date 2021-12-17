import { importJwk } from '../crypto'
import { NrError } from '../errors'
import { JWK } from '../types'
import { jsonSort } from './jsonSort'

export async function parseJwk (jwk: JWK, stringify: boolean = true): Promise<string> {
  try {
    await importJwk(jwk, jwk.alg)
    const sortedJwk = jsonSort(jwk)
    return (stringify) ? JSON.stringify(sortedJwk) : sortedJwk
  } catch (error) {
    throw new NrError(error, ['invalid key'])
  }
}
