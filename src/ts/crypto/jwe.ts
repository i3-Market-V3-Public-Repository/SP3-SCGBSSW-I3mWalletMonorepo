import { compactDecrypt, CompactDecryptResult, CompactEncrypt, decodeProtectedHeader } from 'jose'
import { ENC_ALGS, KEY_AGREEMENT_ALGS, SIGNING_ALGS } from '../constants.js'
import { NrError } from '../errors/index.js'
import { EncryptionAlg, JWK } from '../types.js'
import { importJwk } from './importJwk.js'

/**
 * Encrypts a block of data to JWE
 *
 * @param block - a block of data to encrypt. Notice that maximum string length is 536870888 bytes. Safe typical upper bound to avoid problems is 320MBytes
 * @param secretOrPublicKey - a one-time secret for encrypting this block or publicKey to encrypt a content encryption key to encrypt the block
 * @param encAlg - the algorithm for content encryption. Only necessary if a public key is provided; otherwise it will be used instead of secretOrPublicKey.alg
 * @returns a Compact JWE
 */
export async function jweEncrypt (block: Uint8Array, secretOrPublicKey: JWK, encAlg?: EncryptionAlg): Promise<string> {
  // const input: Uint8Array = (typeof block === 'string') ? (new TextEncoder()).encode(block) : new Uint8Array(block)
  let alg: 'dir' | 'ECDH-ES'
  let enc: EncryptionAlg

  const jwk = { ...secretOrPublicKey }

  if ((ENC_ALGS as unknown as string[]).includes(secretOrPublicKey.alg)) {
    // this is a symmetric secret
    alg = 'dir'
    enc = encAlg !== undefined ? encAlg : secretOrPublicKey.alg as EncryptionAlg
  } else if ((SIGNING_ALGS as unknown as string[]).concat(KEY_AGREEMENT_ALGS).includes(secretOrPublicKey.alg)) {
    // It is a public key
    if (encAlg === undefined) {
      throw new NrError('An encryption algorith encAlg for content encryption should be provided. Allowed values are: ' + ENC_ALGS.join(','), ['encryption failed'])
    }
    enc = encAlg
    alg = 'ECDH-ES'
    jwk.alg = alg as any
  } else {
    throw new NrError(`Not a valid symmetric or assymetric alg: ${secretOrPublicKey.alg as string}`, ['encryption failed', 'invalid key', 'invalid algorithm'])
  }
  const key = await importJwk(jwk)

  let jwe
  try {
    jwe = await new CompactEncrypt(block)
      .setProtectedHeader({ alg, enc, kid: secretOrPublicKey.kid })
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
  try {
    const jwk = { ...secretOrPrivateKey }
    const { alg, enc } = decodeProtectedHeader(jwe)
    if (alg === undefined || enc === undefined) {
      throw new NrError('missing enc or alg in jwe header', ['invalid format'])
    }
    if (alg === 'ECDH-ES') {
      jwk.alg = alg as any
    }
    const key = await importJwk(jwk)

    return await compactDecrypt(jwe, key, { contentEncryptionAlgorithms: [enc] })
  } catch (error) {
    const nrError = new NrError(error, ['decryption failed'])
    throw nrError
  }
}
