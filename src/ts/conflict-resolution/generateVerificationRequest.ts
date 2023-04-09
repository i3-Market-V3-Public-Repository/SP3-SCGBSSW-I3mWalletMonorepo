import { importJWK, JWTPayload, SignJWT } from 'jose'
import { JWK, VerificationRequestPayload } from '../types.js'

export async function generateVerificationRequest (iss: 'orig' | 'dest', dataExchangeId: string, por: string, privateJwk: JWK): Promise<string> {
  const payload: VerificationRequestPayload = {
    proofType: 'request',
    iss,
    dataExchangeId,
    por,
    type: 'verificationRequest',
    iat: Math.floor(Date.now() / 1000)
  }

  const privateKey = await importJWK(privateJwk)

  return await new SignJWT(payload as unknown as JWTPayload)
    .setProtectedHeader({ alg: privateJwk.alg })
    .setIssuedAt(payload.iat)
    .sign(privateKey)
}
