import { compactDecrypt, CompactDecryptResult, CompactEncrypt } from 'jose'
import { EncryptionAlg, JWK } from '../types'
import { NrError } from '../errors'
import { importJwk } from './importJwk'

/**
 * Encrypts a block of data to JWE
 *
 * @param block - the actual block of data
 * @param secret - a one-time secret for encrypting this block
 * @param encAlg - the algorithm for encryption
 * @returns a Compact JWE
 */
export async function jweEncrypt (block: Uint8Array, secret: JWK, encAlg: EncryptionAlg): Promise<string> {
  // const input: Uint8Array = (typeof block === 'string') ? (new TextEncoder()).encode(block) : new Uint8Array(block)
  const key = await importJwk(secret)

  let jwe

  try {
    jwe = await new CompactEncrypt(block)
      .setProtectedHeader({ alg: 'dir', enc: encAlg, kid: secret.kid })
      .encrypt(key)
    return jwe
  } catch (error) {
    throw new NrError(error, ['encryption failed'])
  }
}

/**
 * Decrypts jwe
 * @param jwe - a JWE
 * @param secret - a JWK with the secret to decrypt this jwe
 * @param encAlg - the algorithm for encryption
 * @returns the plaintext
 */
export async function jweDecrypt (jwe: string, secret: JWK, encAlg: EncryptionAlg = 'A256GCM'): Promise<CompactDecryptResult> {
  const key = await importJwk(secret)
  try {
    return await compactDecrypt(jwe, key, { contentEncryptionAlgorithms: [encAlg] })
  } catch (error) {
    const nrError = new NrError(error, ['decryption failed'])
    throw nrError
  }
}
