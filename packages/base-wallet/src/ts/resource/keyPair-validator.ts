import { KeyPairResource } from '../app'
import { Validator } from './resource-validator'
import { digest } from 'object-sha'
import { verifyKeyPair } from '@i3m/non-repudiation-library'

export const keyPairValidator: Validator<KeyPairResource> = async (resource, veramo) => {
  const errors: Error[] = []

  try {
    const { keyPair } = resource.resource

    // Verify keyPair
    await verifyKeyPair(JSON.parse(keyPair.publicJwk), JSON.parse(keyPair.privateJwk))

    // Let us use a unique id that can be easily found. This way it can be easily linked to contracts added later
    resource.id = await digest(keyPair.publicJwk)
  } catch (error) {
    errors.push(new Error(typeof error === 'string' ? error : 'unknown validation error'))
  }

  return errors
}
