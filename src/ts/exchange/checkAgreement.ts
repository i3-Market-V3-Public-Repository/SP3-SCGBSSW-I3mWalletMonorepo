import { ENC_ALGS, HASH_ALGS, SIGNING_ALGS } from '../constants'
import { NrError } from '../errors'
import { DataExchangeAgreement } from '../types'
import { parseHex, parseJwk } from '../utils'

function parseTimestamp (timestamp: number | string): number {
  if ((new Date(timestamp)).getTime() > 0) {
    return Number(timestamp)
  } else {
    throw new NrError(new Error('invalid timestamp'), ['invalid timestamp'])
  }
}

export async function parseAgreement (agreement: DataExchangeAgreement): Promise<DataExchangeAgreement> {
  const parsedAgreement: DataExchangeAgreement = { ...agreement }
  const agreementClaims = Object.keys(parsedAgreement)
  if (agreementClaims.length < 10 || agreementClaims.length > 11) {
    throw new NrError(new Error('Invalid agreeemt: ' + JSON.stringify(agreement, undefined, 2)), ['invalid format'])
  }
  for (const key of agreementClaims) {
    switch (key) {
      case 'orig':
      case 'dest':
        parsedAgreement[key] = await parseJwk(JSON.parse(agreement[key]), true)
        break
      case 'ledgerContractAddress':
      case 'ledgerSignerAddress':
        parsedAgreement[key] = parseHex(parsedAgreement[key], true)
        break
      case 'pooToPorDelay':
      case 'pooToPopDelay':
      case 'pooToSecretDelay':
        parsedAgreement[key] = parseTimestamp(parsedAgreement[key])
        break
      case 'hashAlg':
        if (!HASH_ALGS.includes(parsedAgreement[key])) {
          throw new NrError(new Error('Invalid hash algorithm'), ['invalid algorithm'])
        }
        break
      case 'encAlg':
        if (!ENC_ALGS.includes(parsedAgreement[key])) {
          throw new NrError(new Error('Invalid hash algorithm'), ['invalid algorithm'])
        }
        break
      case 'signingAlg':
        if (!SIGNING_ALGS.includes(parsedAgreement[key])) {
          throw new NrError(new Error('Invalid hash algorithm'), ['invalid algorithm'])
        }
        break
      case 'schema':
        break
      default:
        throw new NrError(new Error(`Property ${key} not allowed in dataAgreement`), ['invalid format'])
    }
  }
  return parsedAgreement
}
