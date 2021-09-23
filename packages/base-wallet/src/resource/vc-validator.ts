import { WalletError } from '../errors'
import { Validator } from './resource-validator'

export const verifiableClaimValidator: Validator = async (resource, veramo) => {
  const errors: Error[] = []

  const subject = resource.resource.credentialSubject.id
  resource.identity = subject

  // Validate verifiable credential
  if (resource.resource === undefined) {
    errors.push(new WalletError(''))
  } else {
    try {
      await veramo.agent.handleMessage({
        raw: resource.resource.proof.jwt
      })
    } catch (ex) {
      errors.push(ex)
    }
  }

  return errors
}
