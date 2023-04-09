import { importJwk } from '../crypto/index.js'
import { NrError } from '../errors/index.js'
import { JWK } from '../types.js'
import { jsonSort } from './jsonSort.js'

export async function parseJwk (jwk: JWK, stringify: true): Promise<string>
export async function parseJwk (jwk: JWK, stringify: false): Promise<JWK>
export async function parseJwk (jwk: JWK, stringify: boolean): Promise<string | JWK> {
  try {
    await importJwk(jwk, jwk.alg)
    const sortedJwk = jsonSort(jwk)
    return (stringify) ? JSON.stringify(sortedJwk) : sortedJwk
  } catch (error) {
    throw new NrError(error, ['invalid key'])
  }
}
