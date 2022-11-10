import { jwsDecode } from '../crypto'
import { NrpDltAgentDest } from '../dlt'
import { exchangeId } from '../exchange'
import { NrError } from '../errors'
import { verifyProof } from '../proofs'
import { Dict, JWK, PoOPayload, PoRPayload } from '../types'
import { checkTimestamp } from '../utils'
import { secretLength } from '../utils/secretLength'

export async function verifyPor (por: string, wallet: NrpDltAgentDest, connectionTimeout = 10): Promise<{ porPayload: PoRPayload, pooPayload: PoOPayload, secretHex: string, destPublicJwk: JWK, origPublicJwk: JWK}> {
  const { payload: porPayload } = await jwsDecode<Dict<PoRPayload>>(por)
  const exchange = porPayload.exchange

  const dataExchangePreview = { ...exchange }
  // @ts-expect-error
  delete dataExchangePreview.id

  const expectedExchangeId = await exchangeId(dataExchangePreview)

  if (expectedExchangeId !== exchange.id) {
    throw new NrError(new Error('data exchange integrity failed'), ['dataExchange integrity violated'])
  }

  const destPublicJwk = JSON.parse(exchange.dest) as JWK
  const origPublicJwk = JSON.parse(exchange.orig) as JWK

  let pooPayload: PoOPayload

  try {
    const verified = await verifyProof<PoOPayload>(porPayload.poo, {
      iss: 'orig',
      proofType: 'PoO',
      exchange
    })
    pooPayload = verified.payload
  } catch (error) {
    throw new NrError(error, ['invalid poo'])
  }

  try {
    await verifyProof<PoRPayload>(por, {
      iss: 'dest',
      proofType: 'PoR',
      exchange
    }, {
      timestamp: 'iat',
      notBefore: pooPayload.iat * 1000,
      notAfter: pooPayload.iat * 1000 + exchange.pooToPorDelay
    })
  } catch (error) {
    throw new NrError(error, ['invalid por'])
  }

  let secretHex: string, iat: number
  try {
    const secret = await wallet.getSecretFromLedger(secretLength(exchange.encAlg), exchange.ledgerSignerAddress, exchange.id, connectionTimeout)
    secretHex = secret.hex
    iat = secret.iat
  } catch (error) {
    throw new NrError(error, ['cannot verify'])
  }

  try {
    checkTimestamp(iat * 1000, porPayload.iat * 1000, pooPayload.iat * 1000 + exchange.pooToSecretDelay)
  } catch (error) {
    throw new NrError(`Although the secret has been obtained (and you could try to decrypt the cipherblock), it's been published later than agreed: ${(new Date(iat * 1000)).toUTCString()} > ${(new Date(pooPayload.iat * 1000 + exchange.pooToSecretDelay)).toUTCString()}`, ['secret not published in time'])
  }

  return {
    pooPayload,
    porPayload,
    secretHex,
    destPublicJwk,
    origPublicJwk
  }
}
