import { NrpDltAgentDest } from '..'
import { jwsDecode } from '../crypto'
import { NrError } from '../errors'
import { JWK, PoOPayload, PoRPayload, VerificationRequestPayload } from '../types'
import { verifyPor } from './verifyPor'

/**
 * Checks the completeness of a given data exchange by verifying the PoR in the verification request using the secret downloaded from the ledger
 *
 * @param verificationRequest
 * @param wallet
 * @returns
 */
export async function checkCompleteness (verificationRequest: string, wallet: NrpDltAgentDest, connectionTimeout = 10): Promise<{ vrPayload: VerificationRequestPayload, porPayload: PoRPayload, pooPayload: PoOPayload, destPublicJwk: JWK, origPublicJwk: JWK}> {
  let vrPayload: VerificationRequestPayload
  try {
    const decoded = await jwsDecode<VerificationRequestPayload>(verificationRequest)
    vrPayload = decoded.payload
  } catch (error) {
    throw new NrError(error, ['invalid verification request'])
  }

  let destPublicJwk, origPublicJwk, pooPayload, porPayload
  try {
    const verified = await verifyPor(vrPayload.por, wallet, connectionTimeout)
    destPublicJwk = verified.destPublicJwk
    origPublicJwk = verified.origPublicJwk
    pooPayload = verified.pooPayload
    porPayload = verified.porPayload
  } catch (error) {
    throw new NrError(error, ['invalid por', 'invalid verification request'])
  }

  try {
    await jwsDecode<VerificationRequestPayload>(verificationRequest, (vrPayload.iss === 'dest') ? destPublicJwk : origPublicJwk)
  } catch (error) {
    throw new NrError(error, ['invalid verification request'])
  }

  return {
    pooPayload,
    porPayload,
    vrPayload,
    destPublicJwk,
    origPublicJwk
  }
}
