import { VerifiableCredential } from '@i3m/base-wallet'

export function getClaims (vc: VerifiableCredential): any {
  return Object
    .entries(vc.credentialSubject)
    .filter(([prop]) => prop !== 'id')
    .reduce((claims: Record<string, any>, [key, value]) => {
      claims[key] = value
      return claims
    }, {})
}
