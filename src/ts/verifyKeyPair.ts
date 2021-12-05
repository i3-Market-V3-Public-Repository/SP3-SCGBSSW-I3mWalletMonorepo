import { GeneralSign, generalVerify, importJWK, JWK } from 'jose'
import { randBytes } from 'bigint-crypto-utils'

export async function verifyKeyPair (pubJWK: JWK, privJWK: JWK): Promise<void> {
  if (pubJWK.alg === undefined || privJWK.alg === undefined || pubJWK.alg !== privJWK.alg) {
    throw new Error('alg no present in either pubJwk or privJwk, or pubJWK.alg != privJWK.alg')
  }
  const pubKey = await importJWK(pubJWK)
  const privKey = await importJWK(privJWK)
  const nonce = await randBytes(16)
  const jws = await new GeneralSign(nonce)
    .addSignature(privKey)
    .setProtectedHeader({ alg: privJWK.alg })
    .sign()

  await generalVerify(jws, pubKey) // if verification fails, it throws JWSSignatureVerificationFailed: signature verification failed
}
