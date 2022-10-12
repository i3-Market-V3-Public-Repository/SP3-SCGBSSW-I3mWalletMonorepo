import { VerifiableCredential } from '@veramo/core'

export function getCredentialClaims (vc: VerifiableCredential): string[] {
  return Object.keys(vc.credentialSubject)
    .filter(claim => claim !== 'id')
}
