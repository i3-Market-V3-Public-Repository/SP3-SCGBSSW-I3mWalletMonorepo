import * as b64 from '@juanelas/base64'
import { hexToBuf } from 'bigint-conversion'
import { randBytes } from 'bigint-crypto-utils'
import elliptic from 'elliptic'
import { NrError } from '../errors'
import { JWK, JwkPair, SigningAlg } from '../types'

const { ec: Ec } = elliptic
/**
 * Generates a pair of JWK signing/verification keys
 *
 * @param alg - the signing algorithm to use
 * @param privateKey - an optional private key as a Uint8Array, or a string (hex or base64)
 * @param base - only used when privateKey is a string. Set to true if the privateKey is base64 encoded (standard base64, url-safe bas64 with and without padding are supported)
 * @returns
 */
export async function generateKeys (alg: SigningAlg, privateKey?: Uint8Array | string, base64?: boolean): Promise<JwkPair> {
  const algs: SigningAlg[] = ['ES256', 'ES384', 'ES512']
  if (!algs.includes(alg)) throw new NrError(new RangeError(`Invalid signature algorithm '${alg}''. Allowed algorithms are ${algs.toString()}`), ['invalid algorithm'])

  let keyLength: number
  let namedCurve: string
  switch (alg) {
    case 'ES512':
      namedCurve = 'P-521'
      keyLength = 66
      break
    case 'ES384':
      namedCurve = 'P-384'
      keyLength = 48
      break
    default:
      namedCurve = 'P-256'
      keyLength = 32
  }

  let privKeyBuf: Uint8Array | CryptoKey
  if (privateKey !== undefined) {
    if (typeof privateKey === 'string') {
      if (base64 === true) {
        privKeyBuf = b64.decode(privateKey) as Uint8Array
      } else {
        privKeyBuf = new Uint8Array(hexToBuf(privateKey))
      }
    } else {
      privKeyBuf = privateKey
    }
  } else {
    privKeyBuf = new Uint8Array(await randBytes(keyLength))
  }

  const ec = new Ec('p' + namedCurve.substring(namedCurve.length - 3))
  const ecPriv = ec.keyFromPrivate(privKeyBuf)
  const ecPub = ecPriv.getPublic()

  const xHex = ecPub.getX().toString('hex').padStart(keyLength * 2, '0')
  const yHex = ecPub.getY().toString('hex').padStart(keyLength * 2, '0')
  const dHex = ecPriv.getPrivate('hex').padStart(keyLength * 2, '0')

  const x = b64.encode(hexToBuf(xHex), true, false)
  const y = b64.encode(hexToBuf(yHex), true, false)
  const d = b64.encode(hexToBuf(dHex), true, false)

  const privateJwk: JWK = { kty: 'EC', crv: namedCurve, x, y, d, alg }

  const publicJwk: JWK = { ...privateJwk }
  delete publicJwk.d

  return {
    publicJwk,
    privateJwk
  }
}
