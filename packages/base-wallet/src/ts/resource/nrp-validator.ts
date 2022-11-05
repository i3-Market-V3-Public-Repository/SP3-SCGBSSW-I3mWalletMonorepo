import { DataExchange, jwsDecode, NrProofPayload } from '@i3m/non-repudiation-library'
import Debug from 'debug'
import { NonRepudiationProofResource } from '../app'
import { validateDataExchange } from '../utils'
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

    const deErrors = await validateDataExchange(decodedProof.payload.exchange)
    if (deErrors.length > 0) {
      deErrors.forEach((error) => {
        errors.push(error)
      })
    } else {
      resource.parentResource = decodedProof.payload.exchange.id

      debug(`Received NRP for data exchange ${decodedProof.payload.exchange.id}:\n` + JSON.stringify(decodedProof.payload.exchange, undefined, 2))
      debug(`  associated to data exchange agreement ${resource.parentResource}`)

      resource.name = decodedProof.payload.proofType
    }
  } catch (error) {
    errors.push(new Error((typeof error === 'string') ? error : JSON.stringify(error, undefined, 2)))
  }

  return errors
}
