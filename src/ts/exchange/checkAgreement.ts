import spec from '@i3m/wallet-desktop-openapi/openapi_dereferenced.json'
import Ajv from 'ajv-draft-04'
import addFormats from 'ajv-formats'
import _ from 'lodash'
import { hashable } from 'object-sha'
import { ENC_ALGS, HASH_ALGS, SIGNING_ALGS } from '../constants.js'
import { NrError } from '../errors/index.js'
import { DataExchange, DataExchangeAgreement, DataSharingAgreement } from '../types.js'
import { parseAddress, parseJwk } from '../utils/index.js'
import { exchangeId } from './exchangeId.js'
import jsonSchema from './oas3.0.3.json'

function parseTimestamp (timestamp: number | string): number {
  if ((new Date(timestamp)).getTime() > 0) {
    return Number(timestamp)
  } else {
    throw new NrError(new Error('invalid timestamp'), ['invalid timestamp'])
  }
}
export async function validateDataSharingAgreementSchema (agreement: DataSharingAgreement): Promise<Error[]> {
  const errors: Error[] = []

  const ajv = new Ajv({ strictSchema: false, removeAdditional: 'all' })
  ajv.addMetaSchema(jsonSchema)

  addFormats(ajv)
  // addKeywords(ajv, ['example'])

  const schema = spec.components.schemas.DataSharingAgreement
  try {
    const validate = ajv.compile(schema)
    const clonedAgreement = _.cloneDeep(agreement)
    const valid = validate(agreement)

    if (!valid) {
      if (validate.errors !== null && validate.errors !== undefined && validate.errors.length > 0) {
        validate.errors.forEach(error => {
          errors.push(new NrError(`[${error.instancePath}] ${error.message ?? 'unknown'}`, ['invalid format']))
        })
      }
    }
    if (hashable(clonedAgreement) !== hashable(agreement)) {
      errors.push(new NrError('Additional claims beyond the schema are not supported', ['invalid format']))
    }
  } catch (error) {
    errors.push(new NrError(error, ['invalid format']))
  }

  return errors
}

export async function validateDataExchange (dataExchange: DataExchange): Promise<Error[]> {
  const errors: NrError[] = []

  try {
    const { id, ...dataExchangeButId } = dataExchange
    if (id !== await exchangeId(dataExchangeButId)) {
      errors.push(new NrError('Invalid dataExchange id', ['cannot verify', 'invalid format']))
    }
    const { blockCommitment, secretCommitment, cipherblockDgst, ...dataExchangeAgreement } = dataExchangeButId
    const deaErrors = await validateDataExchangeAgreement(dataExchangeAgreement)
    if (deaErrors.length > 0) {
      deaErrors.forEach((error) => {
        errors.push(error)
      })
    }
  } catch (error) {
    errors.push(new NrError('Invalid dataExchange', ['cannot verify', 'invalid format']))
  }
  return errors
}

export async function validateDataExchangeAgreement (agreement: DataExchangeAgreement): Promise<NrError[]> {
  const errors: NrError[] = []
  const agreementClaims = Object.keys(agreement)
  if (agreementClaims.length < 10 || agreementClaims.length > 11) {
    errors.push(new NrError(new Error('Invalid agreeemt: ' + JSON.stringify(agreement, undefined, 2)), ['invalid format']))
  }
  for (const key of agreementClaims) {
    let parsedAddress: string
    switch (key) {
      case 'orig':
      case 'dest':
        try {
          if (agreement[key] !== await parseJwk(JSON.parse(agreement[key]), true)) {
            errors.push(new NrError(`[dataExchangeAgreeement.${key}] A valid stringified JWK must be provided. For uniqueness, JWK claims must be alphabetically sorted in the stringified JWK. You can use the parseJWK(jwk, true) for that purpose.\n${agreement[key]}`, ['invalid key', 'invalid format']))
          }
        } catch (error) {
          errors.push(new NrError(`[dataExchangeAgreeement.${key}] A valid stringified JWK must be provided. For uniqueness, JWK claims must be alphabetically sorted in the stringified JWK. You can use the parseJWK(jwk, true) for that purpose.`, ['invalid key', 'invalid format']))
        }
        break
      case 'ledgerContractAddress':
      case 'ledgerSignerAddress':
        try {
          parsedAddress = parseAddress(agreement[key])
          if (agreement[key] !== parsedAddress) {
            errors.push(new NrError(`[dataExchangeAgreeement.${key}] Invalid EIP-55 address ${agreement[key]}. Did you mean ${parsedAddress} instead?`, ['invalid EIP-55 address', 'invalid format']))
          }
        } catch (error) {
          errors.push(new NrError(`[dataExchangeAgreeement.${key}] Invalid EIP-55 address ${agreement[key]}.`, ['invalid EIP-55 address', 'invalid format']))
        }
        break
      case 'pooToPorDelay':
      case 'pooToPopDelay':
      case 'pooToSecretDelay':
        try {
          if (agreement[key] !== parseTimestamp(agreement[key])) {
            errors.push(new NrError(`[dataExchangeAgreeement.${key}] < 0 or not a number`, ['invalid timestamp', 'invalid format']))
          }
        } catch (error) {
          errors.push(new NrError(`[dataExchangeAgreeement.${key}] < 0 or not a number`, ['invalid timestamp', 'invalid format']))
        }
        break
      case 'hashAlg':
        if (!HASH_ALGS.includes(agreement[key])) {
          errors.push(new NrError(`[dataExchangeAgreeement.${key}Invalid hash algorithm '${agreement[key]}'. It must be one of: ${HASH_ALGS.join(', ')}`, ['invalid algorithm']))
        }
        break
      case 'encAlg':
        if (!ENC_ALGS.includes(agreement[key])) {
          errors.push(new NrError(`[dataExchangeAgreeement.${key}Invalid encryption algorithm '${agreement[key]}'. It must be one of: ${ENC_ALGS.join(', ')}`, ['invalid algorithm']))
        }
        break
      case 'signingAlg':
        if (!SIGNING_ALGS.includes(agreement[key])) {
          errors.push(new NrError(`[dataExchangeAgreeement.${key}Invalid signing algorithm '${agreement[key]}'. It must be one of: ${SIGNING_ALGS.join(', ')}`, ['invalid algorithm']))
        }
        break
      case 'schema':
        break
      default:
        errors.push(new NrError(new Error(`Property ${key} not allowed in dataAgreement`), ['invalid format']))
    }
  }
  return errors
}
