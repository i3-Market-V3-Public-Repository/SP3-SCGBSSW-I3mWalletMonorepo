import { compactDecrypt, CompactDecryptResult, CompactEncrypt, importJWK, JWK } from 'jose'
import { EncryptionAlg } from './types'

/**
 * Encrypts block to JWE
 *
 * @param exchangeId - the id of the data exchange
 * @param block - the actual block of data
 * @param secret - a one-time secret for encrypting this block
 * @param encAlg - the algorithm for encryption
 * @returns a Compact JWE
 */
export async function jweEncrypt (block: Uint8Array, secret: JWK, encAlg: EncryptionAlg): Promise<string> {
  // const input: Uint8Array = (typeof block === 'string') ? (new TextEncoder()).encode(block) : new Uint8Array(block)
  const key = await importJWK(secret)
  return await new CompactEncrypt(block)
    .setProtectedHeader({ alg: 'dir', enc: encAlg, kid: secret.kid })
    .encrypt(key)
}

/**
 * Decrypts jwe
 * @param jwe - a JWE
 * @param secret - a JWK with the secret to decrypt this jwe
 * @param encAlg - the algorithm for encryption
 * @returns the plaintext
 */
export async function jweDecrypt (jwe: string, secret: JWK, encAlg: EncryptionAlg = 'A256GCM'): Promise<CompactDecryptResult> {
  const key = await importJWK(secret)
  return await compactDecrypt(jwe, key, { contentEncryptionAlgorithms: [encAlg] })
}
