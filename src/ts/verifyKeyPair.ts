import { GeneralSign, generalVerify, importJWK, JWK } from 'jose'
import { randBytes } from 'bigint-crypto-utils'
import { bufToHex } from 'bigint-conversion'

export async function verifyKeyPair (pubJWK: JWK, privJWK: JWK, alg?: string): Promise<void> {
  const pubKey = await importJWK(pubJWK, alg)
  const privKey = await importJWK(privJWK, alg)
  const nonce = await randBytes(16)
  const jws = await new GeneralSign(nonce)
    .addSignature(privKey)
    .setProtectedHeader({ alg: privJWK.alg })
    .sign()

  const { payload } = await generalVerify(jws, pubKey)
  if (bufToHex(payload) !== bufToHex(nonce)) {
    throw new Error(`verified nonce ${bufToHex(payload)} does not meet the one challenged ${bufToHex(nonce)}`)
  }
}
