import { randBytes } from 'bigint-crypto-utils'
import { GeneralSign, generalVerify } from 'jose'
import { importJwk } from './importJwk'
import { NrError } from '../errors'
import { JWK } from '../types'

export async function verifyKeyPair (pubJWK: JWK, privJWK: JWK): Promise<void> {
  if (pubJWK.alg === undefined || privJWK.alg === undefined || pubJWK.alg !== privJWK.alg) {
    throw new Error('alg no present in either pubJwk or privJwk, or pubJWK.alg != privJWK.alg')
  }
  const pubKey = await importJwk(pubJWK)
  const privKey = await importJwk(privJWK)

  try {
    const nonce = await randBytes(16)
    const jws = await new GeneralSign(nonce)
      .addSignature(privKey)
      .setProtectedHeader({ alg: privJWK.alg })
      .sign()
    await generalVerify(jws, pubKey) // if verification fails, it throws JWSSignatureVerificationFailed: signature verification failed
  } catch (error) {
    throw new NrError(error, ['unexpected error'])
  }
}
