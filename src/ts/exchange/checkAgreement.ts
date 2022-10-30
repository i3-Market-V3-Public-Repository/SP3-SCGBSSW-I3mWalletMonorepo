import { ENC_ALGS, HASH_ALGS, SIGNING_ALGS } from '../constants'
import { NrError } from '../errors'
import { DataExchangeAgreement } from '../types'
import { parseAddress, parseJwk } from '../utils'

function parseTimestamp (timestamp: number | string): number {
  if ((new Date(timestamp)).getTime() > 0) {
    return Number(timestamp)
  } else {
    throw new NrError(new Error('invalid timestamp'), ['invalid timestamp'])
  }
}

export async function validateAgreement (agreement: DataExchangeAgreement): Promise<void> {
  const agreementClaims = Object.keys(agreement)
  if (agreementClaims.length < 10 || agreementClaims.length > 11) {
    throw new NrError(new Error('Invalid agreeemt: ' + JSON.stringify(agreement, undefined, 2)), ['invalid format'])
  }
  for (const key of agreementClaims) {
    let parsedAddress: string
    switch (key) {
      case 'orig':
      case 'dest':
        if (agreement[key] !== await parseJwk(JSON.parse(agreement[key]), true)) {
          throw new NrError(`[dataExchangeAgreeement.${key}] A valid stringified JWK must be provided. For uniqueness, JWK claims must be sorted in the stringified JWK. You can use the parseJWK(jwk, true) for that purpose`, ['invalid key', 'invalid format'])
        }
        break
      case 'ledgerContractAddress':
      case 'ledgerSignerAddress':
        try {
          parsedAddress = parseAddress(agreement[key])
        } catch (error) {
          throw new NrError((error as Error).message, ['invalid format'])
        }
        if (agreement[key] !== parsedAddress) {
          throw new NrError(`[dataExchangeAgreeement.${key}] Invalid EIP-55 address ${agreement[key]}. Did you mean ${parsedAddress} instead?`, ['invalid format'])
        }
        break
      case 'pooToPorDelay':
      case 'pooToPopDelay':
      case 'pooToSecretDelay':
        if (agreement[key] !== parseTimestamp(agreement[key])) {
          throw new NrError(`[dataExchangeAgreeement.${key}] < 0 or not a number`, ['invalid format'])
        }
        break
      case 'hashAlg':
        if (!HASH_ALGS.includes(agreement[key])) {
          throw new NrError(new Error('Invalid hash algorithm'), ['invalid algorithm'])
        }
        break
      case 'encAlg':
        if (!ENC_ALGS.includes(agreement[key])) {
          throw new NrError(new Error('Invalid hash algorithm'), ['invalid algorithm'])
        }
        break
      case 'signingAlg':
        if (!SIGNING_ALGS.includes(agreement[key])) {
          throw new NrError(new Error('Invalid hash algorithm'), ['invalid algorithm'])
        }
        break
      case 'schema':
        break
      default:
        throw new NrError(new Error(`Property ${key} not allowed in dataAgreement`), ['invalid format'])
    }
  }
}
