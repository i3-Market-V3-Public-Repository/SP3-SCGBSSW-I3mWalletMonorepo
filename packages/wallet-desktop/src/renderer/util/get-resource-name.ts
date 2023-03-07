import { Resource } from '@i3m/base-wallet'

export function getResourceName (resource: Resource): string {
  let name: string
  if (resource.name !== undefined) {
    name = resource.name
  } else if (resource.type === 'VerifiableCredential') {
    name = Object
      .keys(resource.resource.credentialSubject)
      .filter(claim => claim !== 'id')
      .join(', ')
  } else {
    name = resource.id
  }

  return `[${resource.type}] ${name}`
}
