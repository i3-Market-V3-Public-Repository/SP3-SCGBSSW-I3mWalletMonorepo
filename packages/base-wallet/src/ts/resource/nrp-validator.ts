import { NonRepudiationProofResource } from '../app'
import { Validator } from './resource-validator'

export const nrpValidator: Validator<NonRepudiationProofResource> = async (resource, veramo) => {
  const errors: Error[] = []

  resource.name = 'POO'

  return errors
}
