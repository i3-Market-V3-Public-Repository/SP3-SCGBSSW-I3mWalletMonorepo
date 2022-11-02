import { compactDecrypt, CompactDecryptResult, CompactEncrypt } from 'jose'
import { EncryptionAlg, JWK } from '../types'
import { NrError } from '../errors'
import { importJwk } from './importJwk'

/**
 * Encrypts a block of data to JWE
 *
 * @param block - a block of data to encrypt
 * @param secretOrPublicKey - a one-time secret for encrypting this block or publicKey to encrypt a content encryption key to encrypt the block
 * @param encAlg - the algorithm for encryption
 * @returns a Compact JWE
 */
export async function jweEncrypt (block: Uint8Array, secretOrPublicKey: JWK, encAlg: EncryptionAlg): Promise<string> {
  // const input: Uint8Array = (typeof block === 'string') ? (new TextEncoder()).encode(block) : new Uint8Array(block)
  let alg: 'dir' | 'ECDH-ES'
  if (secretOrPublicKey.alg === 'A128GCM' || secretOrPublicKey.alg === 'A256GCM') {
    // this is a symmetric secret
    alg = 'dir'
  } else if (secretOrPublicKey.alg === 'ES256' || secretOrPublicKey.alg === 'ES384' || secretOrPublicKey.alg === 'ES512') {
    alg = 'ECDH-ES'
  } else {
    throw new NrError(`Not a valid symmetric or assymetric alg: ${secretOrPublicKey.alg as string}`, ['encryption failed', 'invalid key', 'invalid algorithm'])
  }

  const key = await importJwk(secretOrPublicKey)

  let jwe

  try {
    jwe = await new CompactEncrypt(block)
      .setProtectedHeader({ alg, enc: encAlg, kid: secretOrPublicKey.kid })
      .encrypt(key)
    return jwe
  } catch (error) {
    throw new NrError(error, ['encryption failed'])
  }
}

/**
 * Decrypts jwe
 * @param jwe - a JWE
 * @param secretOrPrivateKey - a one-time secret for decrypting this block or a privateKey to decrypt a content encryption key and then decrypt the block
 * @returns the plaintext
 */
export async function jweDecrypt (jwe: string, secretOrPrivateKey: JWK): Promise<CompactDecryptResult> {
  const key = await importJwk(secretOrPrivateKey)
  try {
    // return await compactDecrypt(jwe, key, { contentEncryptionAlgorithms: [encAlg] })
    return await compactDecrypt(jwe, key)
  } catch (error) {
    const nrError = new NrError(error, ['decryption failed'])
    throw nrError
  }
}
