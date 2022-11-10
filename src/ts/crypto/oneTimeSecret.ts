import * as b64 from '@juanelas/base64'
import { decode as base64decode } from '@juanelas/base64'
import { bufToHex, hexToBuf, parseHex } from 'bigint-conversion'
import { exportJWK, generateSecret, KeyLike } from 'jose'
import { ENC_ALGS } from '../constants'
import { NrError } from '../errors'
import { Block, EncryptionAlg, JWK } from '../types'
import { algByteLength } from '../utils/algByteLength'

/**
 * Create a JWK random (high entropy) symmetric secret
 *
 * @param encAlg - the encryption algorithm
 * @param secret - and optional seed as Uint8Array or string (hex or base64)
 * @param base64 - if a secret is provided as a string, sets base64 decoding. It supports standard, url-safe base64 with and without padding (autodetected).
 * @returns a promise that resolves to the secret in JWK and raw hex string
 */

export async function oneTimeSecret (encAlg: EncryptionAlg, secret?: Uint8Array|string, base64?: boolean): Promise<Exclude<Block['secret'], undefined>> {
  let key: Uint8Array | KeyLike

  if (!ENC_ALGS.includes(encAlg)) {
    throw new NrError(new Error(`Invalid encAlg '${encAlg as string}'. Supported values are: ${ENC_ALGS.toString()}`), ['invalid algorithm'])
  }

  const secretLength = algByteLength(encAlg)

  if (secret !== undefined) {
    if (typeof secret === 'string') {
      if (base64 === true) {
        key = b64.decode(secret) as Uint8Array
      } else { // The secret is provided as hex
        const parsedSecret = parseHex(secret, false)
        if (parsedSecret !== parseHex(secret, false, secretLength)) {
          throw new NrError(new RangeError(`Expected hex length ${secretLength * 2} does not meet provided one ${parsedSecret.length / 2}`), ['invalid key'])
        }
        key = new Uint8Array(hexToBuf(secret))
      }
    } else {
      key = secret
    }
    if (key.length !== secretLength) {
      throw new NrError(new RangeError(`Expected secret length ${secretLength} does not meet provided one ${key.length}`), ['invalid key'])
    }
  } else {
    try {
      key = await generateSecret(encAlg, { extractable: true })
    } catch (error) {
      throw new NrError(error, ['unexpected error'])
    }
  }
  const jwk = await exportJWK(key)
  // const thumbprint: string = await calculateJwkThumbprint(jwk)
  // jwk.kid = thumbprint
  jwk.alg = encAlg

  return { jwk: jwk as JWK, hex: bufToHex(base64decode(jwk.k as string) as Uint8Array, false, secretLength) }
}
