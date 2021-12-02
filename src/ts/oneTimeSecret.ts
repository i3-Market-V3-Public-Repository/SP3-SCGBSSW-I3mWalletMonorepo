import { calculateJwkThumbprint, exportJWK, generateSecret, JWK, KeyLike } from 'jose'
import { ENC_ALG } from './constants'

/**
 * Create a random (high entropy) symmetric JWK secret for AES-256-GCM
 *
 * @returns a promise that resolves to a JWK
 */

export async function oneTimeSecret (): Promise<JWK> {
  const key = await generateSecret(ENC_ALG, { extractable: true }) as KeyLike
  const jwk: JWK = await exportJWK(key)
  const thumbprint: string = await calculateJwkThumbprint(jwk)
  jwk.kid = thumbprint
  jwk.alg = ENC_ALG

  return jwk
}
