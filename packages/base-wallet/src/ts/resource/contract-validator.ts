import { ContractResource } from '../app'
import { validateDataSharingAgreeementSchema, verifyDataSharingAgreementSignature } from '../utils'
import { Validator } from './resource-validator'
import { digest } from 'object-sha'

export const contractValidator: Validator<ContractResource> = async (resource, veramo) => {
  const errors: Error[] = []

  try {
    // Verify schema
    const schemaValidationErrors = await validateDataSharingAgreeementSchema(resource.resource)
    if (schemaValidationErrors.length > 0) return schemaValidationErrors

    // Check role of the identity in the agreeement (whether it is 'provider' or 'consumer')
    let role: 'provider' | 'consumer' | '' = ''
    if (resource.identity === resource.resource.parties.consumerDid) role = 'consumer'
    if (resource.identity === resource.resource.parties.providerDid) {
      if (role === 'consumer') errors.push(new Error('the same identity cannot be at the same time the consumer and the provider'))
      role = 'provider'
    }

    // Verify that the resource is added to an existing identity (DID) which is the provider or the consumer of the agreement
    if (role === '') {
      errors.push(new Error('the resource MUST be associated to an existing identity that is either the consumer or the provider'))
      return errors
    }

    // Verify the agreement's signatures
    const provSigVerificationErrors = await verifyDataSharingAgreementSignature(resource.resource, veramo, 'provider')
    provSigVerificationErrors.forEach(err => { errors.push(err) })
    const consSigVerificationErrors = await verifyDataSharingAgreementSignature(resource.resource, veramo, 'consumer')
    consSigVerificationErrors.forEach(err => { errors.push(err) })

    // Let us change the resource name to something more human readable (instead of a uuid)
    resource.name = `[${role}] ${resource.resource.dataOfferingDescription.title ?? resource.resource.dataOfferingDescription.dataOfferingId}`

    // Let us use a unique id that can be easily found. This way it can be easily linked to NR proofs
    resource.id = await digest(resource.resource.dataExchangeAgreement)
  } catch (error) {
    errors.push(new Error(typeof error === 'string' ? error : 'unknown validation error'))
  }

  return errors
}
