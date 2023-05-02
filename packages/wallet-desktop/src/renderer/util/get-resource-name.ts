import { Resource } from '@i3m/base-wallet'

export function getResourceName (resource: Resource, doNotAddType: boolean = false): string {
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

  return doNotAddType ? name : `[${resource.type}] ${name}`
}
