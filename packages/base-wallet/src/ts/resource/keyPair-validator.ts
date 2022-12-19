import { KeyPairResource } from '../app'
import { Validator } from './resource-validator'
import { digest } from 'object-sha'
import { parseJwk, verifyKeyPair } from '@i3m/non-repudiation-library'

export const keyPairValidator: Validator<KeyPairResource> = async (resource, veramo) => {
  const errors: Error[] = []

  try {
    const { keyPair } = resource.resource

    const publicJwk = JSON.parse(keyPair.publicJwk)
    const privateJwk = JSON.parse(keyPair.privateJwk)

    // Verify keyPair
    await verifyKeyPair(publicJwk, privateJwk)

    // Let us rewrite the JWK strings in sorted order
    keyPair.publicJwk = await parseJwk(publicJwk, true)
    keyPair.privateJwk = await parseJwk(privateJwk, true)

    // Let us use a unique id that can be easily found. This way it can be easily linked to contracts added later
    resource.id = await digest(keyPair.publicJwk)
  } catch (error) {
    errors.push(new Error(typeof error === 'string' ? error : 'unknown validation error'))
  }

  return errors
}
