import { compactDecrypt, CompactDecryptResult, CompactEncrypt } from 'jose'
import { EncryptionAlg, JWK } from '../types'
import { NrError } from '../errors'
import { importJwk } from './importJwk'
import { ENC_ALGS, SIGNING_ALGS } from '../constants'

/**
 * Encrypts a block of data to JWE
 *
 * @param block - a block of data to encrypt
 * @param secretOrPublicKey - a one-time secret for encrypting this block or publicKey to encrypt a content encryption key to encrypt the block
 * @param encAlg - the algorithm for content encryption
 * @returns a Compact JWE
 */
export async function jweEncrypt (block: Uint8Array, secretOrPublicKey: JWK, encAlg: EncryptionAlg): Promise<string> {
  // const input: Uint8Array = (typeof block === 'string') ? (new TextEncoder()).encode(block) : new Uint8Array(block)
  let alg: 'dir' | 'ECDH-ES'

  const jwk = { ...secretOrPublicKey }

  if ((ENC_ALGS as unknown as string[]).includes(secretOrPublicKey.alg)) {
    // this is a symmetric secret
    alg = 'dir'
  } else if ((SIGNING_ALGS as unknown as string[]).includes(secretOrPublicKey.alg)) {
    alg = 'ECDH-ES'
    jwk.alg = alg as any
    // jwk.use = 'enc'
    // jwk.ext = true
    // jwk.key_ops = ['wrapKey', 'encrypt', 'deriveBits', 'deriveKey']
  } else {
    throw new NrError(`Not a valid symmetric or assymetric alg: ${secretOrPublicKey.alg as string}`, ['encryption failed', 'invalid key', 'invalid algorithm'])
  }
  const key = await importJwk(jwk)

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
 * @param encAlg - the algorithm used for contentEncryption
 * @returns the plaintext
 */
export async function jweDecrypt (jwe: string, secretOrPrivateKey: JWK, encAlg: EncryptionAlg = 'A256GCM'): Promise<CompactDecryptResult> {
  try {
    const jwk = { ...secretOrPrivateKey }

    if ((SIGNING_ALGS as unknown as string[]).includes(secretOrPrivateKey.alg)) {
      jwk.alg = 'ECDH-ES' as any
      // jwk.use = 'enc'
      // jwk.ext = true
      // jwk.key_ops = ['wrapKey', 'encrypt', 'deriveBits', 'deriveKey']
    } else if (!(ENC_ALGS as unknown as string[]).includes(secretOrPrivateKey.alg)) {
      throw new NrError(`Not a valid symmetric or assymetric alg: ${secretOrPrivateKey.alg as string}`, ['decryption failed', 'invalid key', 'invalid algorithm'])
    }
    const key = await importJwk(jwk)

    return await compactDecrypt(jwe, key, { contentEncryptionAlgorithms: [encAlg] })
    // return await compactDecrypt(jwe, key)
  } catch (error) {
    const nrError = new NrError(error, ['decryption failed'])
    throw nrError
  }
}
