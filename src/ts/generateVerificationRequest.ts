import { importJWK, SignJWT } from 'jose'
import { JWK, VerificationRequestPayload } from './types'

export default async function generateVerificationRequest (iss: 'orig' | 'dest', por: string, privateJwk: JWK): Promise<string> {
  const payload: VerificationRequestPayload = {
    iss,
    por,
    type: 'verificationRequest',
    iat: Math.floor(Date.now() / 1000)
  }

  const privateKey = await importJWK(privateJwk)

  return await new SignJWT(payload)
    .setProtectedHeader({ alg: privateJwk.alg })
    .setIssuedAt(payload.iat)
    .sign(privateKey)
}
