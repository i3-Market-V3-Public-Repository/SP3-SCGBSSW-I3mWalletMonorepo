import { calculateJwkThumbprint, exportJWK, generateSecret, JWK } from 'jose'
import { bufToHex } from 'bigint-conversion'
import { decode as base64decode } from '@juanelas/base64'
import { Block, EncryptionAlg } from './types'

/**
 * Create a random (high entropy) symmetric secret for AES-256-GCM
 *
 * @returns a promise that resolves to the secret in JWK and raw hex string
 */

export async function oneTimeSecret (encAlg: EncryptionAlg): Promise<Exclude<Block['secret'], undefined>> {
  const key = await generateSecret(encAlg, { extractable: true })
  const jwk: JWK = await exportJWK(key)
  const thumbprint: string = await calculateJwkThumbprint(jwk)
  jwk.kid = thumbprint
  jwk.alg = encAlg

  return { jwk, hex: bufToHex(base64decode(jwk.k as string) as Uint8Array) }
}
