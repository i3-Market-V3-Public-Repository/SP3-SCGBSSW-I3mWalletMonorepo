import { Contract } from 'ethers'
import { jwsDecode } from '../crypto'
import { getSecretFromLedger } from '../dlt'
import { exchangeId } from '../exchange'
import { NrError } from '../errors'
import { verifyProof } from '../proofs'
import { Dict, JWK, PoOPayload, PoRPayload } from '../types'
import { checkIssuedAt } from '../utils'

export async function verifyPor (por: string, dltContract: Contract): Promise<{ porPayload: PoRPayload, pooPayload: PoOPayload, secretHex: string, destPublicJwk: JWK, origPublicJwk: JWK}> {
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
    })
  } catch (error) {
    throw new NrError(error, ['invalid por'])
  }

  let secretHex: string, iat: number
  try {
    const secret = await getSecretFromLedger(dltContract, exchange.ledgerSignerAddress, exchange.id)
    secretHex = secret.hex
    iat = secret.iat
  } catch (error) {
    throw new NrError(error, ['cannot verify'])
  }

  try {
    checkIssuedAt(iat, {
      clockToleranceMs: 0, // The ledger time is what it counts
      expectedTimestampInterval: {
        min: pooPayload.iat * 1000,
        max: pooPayload.iat * 1000 + exchange.pooToSecretDelay
      }
    })
  } catch (error) {
    throw new NrError(error, ['secret not published in time'])
  }

  return {
    pooPayload,
    porPayload,
    secretHex,
    destPublicJwk,
    origPublicJwk
  }
}
