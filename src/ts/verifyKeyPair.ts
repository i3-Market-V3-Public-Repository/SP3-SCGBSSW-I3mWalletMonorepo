import { GeneralSign, generalVerify, importJWK, JWK } from 'jose'
import { randBytes } from 'bigint-crypto-utils'

export async function verifyKeyPair (pubJWK: JWK, privJWK: JWK, alg?: string): Promise<void> {
  const pubKey = await importJWK(pubJWK, alg)
  const privKey = await importJWK(privJWK, alg)
  const nonce = await randBytes(16)
  const jws = await new GeneralSign(nonce)
    .addSignature(privKey)
    .setProtectedHeader({ alg: privJWK.alg })
    .sign()

  await generalVerify(jws, pubKey) // if verification fails, it throws JWSSignatureVerificationFailed: signature verification failed
}
