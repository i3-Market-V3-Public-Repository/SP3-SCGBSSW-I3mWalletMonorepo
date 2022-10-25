import { ContractResource } from '../app'
import { validateDataSharingAgreeementSchema, verifyDataSharingAgreementSignature } from '../utils'
import { Validator } from './resource-validator'

export const contractValidator: Validator<ContractResource> = async (resource, veramo) => {
  const errors: Error[] = []

  try {
    const schemaValidationErrors = await validateDataSharingAgreeementSchema(resource.resource)
    if (schemaValidationErrors.length > 0) return schemaValidationErrors

    const provSigVerificationErrors = await verifyDataSharingAgreementSignature(resource.resource, veramo, 'provider')
    const consSigVerificationErrors = await verifyDataSharingAgreementSignature(resource.resource, veramo, 'consumer')

    provSigVerificationErrors.forEach(err => { errors.push(err) })
    consSigVerificationErrors.forEach(err => { errors.push(err) })
  } catch (error) {
    errors.push(new Error(typeof error === 'string' ? error : 'unknown validation error'))
  }

  return errors
}
