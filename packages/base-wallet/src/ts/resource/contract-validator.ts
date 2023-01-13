/* eslint-disable @typescript-eslint/no-non-null-assertion */

import { ContractResource } from '../app'
import { verifyDataSharingAgreementSignature } from '../utils'
import { Validator } from './resource-validator'
import { digest } from 'object-sha'
import { verifyKeyPair, validateDataSharingAgreementSchema, validateDataExchangeAgreement } from '@i3m/non-repudiation-library'

export const contractValidator: Validator<ContractResource> = async (resource, veramo) => {
  const errors: Error[] = []

  try {
    const { dataSharingAgreement, keyPair } = resource.resource

    // Verify schema
    const schemaValidationErrors = await validateDataSharingAgreementSchema(dataSharingAgreement)
    if (schemaValidationErrors.length > 0) return schemaValidationErrors

    if (dataSharingAgreement.parties.consumerDid === dataSharingAgreement.parties.providerDid) {
      throw new Error('the same identity cannot be at the same time the consumer and the provider')
    }

    // Validate dataExchangeAgreemeent
    const deaErrors = await validateDataExchangeAgreement(dataSharingAgreement.dataExchangeAgreement)
    if (deaErrors.length > 0) {
      deaErrors.forEach((error) => {
        errors.push(error)
      })
    }

    // Check role
    let role: 'provider' | 'consumer'
    if (keyPair!.publicJwk === dataSharingAgreement.dataExchangeAgreement.orig) {
      role = 'provider'
    } else if (keyPair!.publicJwk === dataSharingAgreement.dataExchangeAgreement.dest) {
      role = 'consumer'
    } else {
      throw new Error(`${keyPair!.publicJwk} is not either dataExchangeAgreement.orig or dataExchangeAgreement.dest`)
    }

    // Verify keyPair
    await verifyKeyPair(JSON.parse(keyPair!.publicJwk), JSON.parse(keyPair!.privateJwk))

    // If an identity is provided, check that is either the provider or the consumer
    if (resource.identity !== undefined) {
      const expectedDid = (role === 'consumer') ? dataSharingAgreement.parties.consumerDid : dataSharingAgreement.parties.providerDid
      if (expectedDid !== resource.identity) {
        throw new Error(`resource.identity does not match dataSharingAgreement.parties.${role}Did`)
      }
    }

    // Verify the agreement's signatures
    const provSigVerificationErrors = await verifyDataSharingAgreementSignature(dataSharingAgreement, veramo, 'provider')
    provSigVerificationErrors.forEach(err => { errors.push(err) })
    const consSigVerificationErrors = await verifyDataSharingAgreementSignature(dataSharingAgreement, veramo, 'consumer')
    consSigVerificationErrors.forEach(err => { errors.push(err) })

    // Let us use a unique id that can be easily found. This way it can be easily linked to NR proofs
    resource.id = await digest(dataSharingAgreement.dataExchangeAgreement)
  } catch (error) {
    errors.push(new Error(typeof error === 'string' ? error : 'unknown validation error'))
  }

  return errors
}
