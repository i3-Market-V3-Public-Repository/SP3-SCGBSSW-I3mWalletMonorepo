import { jweDecrypt, jwsDecode, oneTimeSecret } from '../crypto'
import { NrError } from '../errors'
import { DisputeRequestPayload, JWK, PoOPayload, PoRPayload } from '../types'
import { sha } from '../utils'
import { verifyPor } from './verifyPor'
import * as b64 from '@juanelas/base64'
import { NrpDltAgentDest } from '../dlt'

/**
 * Check if the cipherblock in the disputeRequest is the one agreed for the dataExchange, and if it could be decrypted with the secret published on the ledger for that dataExchange.
 *
 * @param disputeRequest a dispute request as a compact JWS
 * @param wallet
 * @returns
 */
export async function checkDecryption (disputeRequest: string, wallet: NrpDltAgentDest): Promise<{ drPayload: DisputeRequestPayload, porPayload: PoRPayload, pooPayload: PoOPayload, destPublicJwk: JWK, origPublicJwk: JWK }> {
  const { payload: drPayload } = await jwsDecode<DisputeRequestPayload>(disputeRequest)

  const {
    destPublicJwk,
    origPublicJwk,
    secretHex,
    pooPayload,
    porPayload
  } = await verifyPor(drPayload.por, wallet)

  try {
    await jwsDecode<DisputeRequestPayload>(disputeRequest, destPublicJwk)
  } catch (error) {
    if (error instanceof NrError) {
      error.add('invalid dispute request')
    }
    throw error
  }

  const cipherblockDgst = b64.encode(await sha(drPayload.cipherblock, porPayload.exchange.hashAlg), true, false)

  if (cipherblockDgst !== porPayload.exchange.cipherblockDgst) {
    throw new NrError(new Error('cipherblock does not meet the committed (and already accepted) one'), ['invalid dispute request'])
  }

  await jweDecrypt(drPayload.cipherblock, (await (oneTimeSecret(porPayload.exchange.encAlg, secretHex))).jwk)

  /**
   * TO-DO: check schema!
   */

  return {
    pooPayload,
    porPayload,
    drPayload,
    destPublicJwk,
    origPublicJwk
  }
}
