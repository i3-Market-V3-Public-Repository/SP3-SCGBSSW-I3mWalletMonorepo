import { DataExchange, exchangeId, jwsDecode, NrProofPayload } from '@i3m/non-repudiation-library'
import Debug from 'debug'
import { digest } from 'object-sha'
import { NonRepudiationProofResource } from '../app'
import { validateDataExchangeAgreement } from '../utils'
import { Validator } from './resource-validator'

const debug = Debug('base-wallet:NrpValidator')

export const nrpValidator: Validator<NonRepudiationProofResource> = async (resource, veramo) => {
  const errors: Error[] = []

  try {
    const jws = resource.resource

    const decodedProof = await jwsDecode<NrProofPayload>(jws, (header, payload) => {
      const key = payload.iss as keyof Pick<DataExchange, 'orig' | 'dest'>
      return JSON.parse(payload.exchange[key])
    })
    const { id, cipherblockDgst, blockCommitment, secretCommitment, ...dataExchangeAgreement } = decodedProof.payload.exchange

    const deaErrors = await validateDataExchangeAgreement(dataExchangeAgreement)
    if (deaErrors.length > 0) {
      deaErrors.forEach((error) => {
        errors.push(error)
      })
    } else {
      // The proof is associated to a given data sharing agreement
      resource.parentResource = await digest(dataExchangeAgreement)

      debug('Received data exchange agreeement:\n' + JSON.stringify(dataExchangeAgreement, undefined, 2))
      debug(`Parent resource id: ${resource.parentResource}`)
      // The proof name is the type along with the dataExchangeId (there could be multiple dataExchanges for the same data sharing agreeement)
      resource.name = `[${decodedProof.payload.proofType}] ${await exchangeId(decodedProof.payload.exchange)}`
    }
  } catch (error) {
    errors.push(new Error((typeof error === 'string') ? error : JSON.stringify(error, undefined, 2)))
  }

  return errors
}
