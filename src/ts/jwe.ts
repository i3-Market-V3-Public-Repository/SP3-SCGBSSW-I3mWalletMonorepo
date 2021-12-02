import { DataExchange } from './types'
import { compactDecrypt, CompactDecryptResult, CompactEncrypt, importJWK, JWK } from 'jose'
import { ENC_ALG } from './constants'

export { CompactDecryptResult }

/**
 * Encrypts block to JWE
 *
 * @param exchangeId - the id of the data exchange
 * @param block - the actual block of data
 * @param secret - a one-time secret for encrypting this block
 * @returns a Compact JWE
 */
export async function jweEncrypt (exchangeId: DataExchange['id'], block: Uint8Array, secret: JWK): Promise<string> {
  // const input: Uint8Array = (typeof block === 'string') ? (new TextEncoder()).encode(block) : new Uint8Array(block)
  const key = await importJWK(secret)
  return await new CompactEncrypt(block)
    .setProtectedHeader({ alg: 'dir', enc: ENC_ALG, exchangeId, kid: secret.kid })
    .encrypt(key)
}

/**
 * Decrypts jwe
 * @param jwe - a JWE
 * @param secret - a JWK with the secret to decrypt this jwe
 * @returns the plaintext
 */
export async function jweDecrypt (jwe: string, secret: JWK): Promise<CompactDecryptResult> {
  const key = await importJWK(secret)
  return await compactDecrypt(jwe, key, { contentEncryptionAlgorithms: [ENC_ALG] })
}
