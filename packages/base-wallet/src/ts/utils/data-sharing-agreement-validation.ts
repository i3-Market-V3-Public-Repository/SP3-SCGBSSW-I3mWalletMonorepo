import { WalletPaths } from '@i3m/wallet-desktop-openapi/types'
import { BaseWalletModel, ContractResource } from '../app'
import { didJwtVerify } from '../utils/did-jwt-verify'
import { Veramo } from '../veramo'

export async function verifyDataSharingAgreementSignature (agreement: ContractResource['resource']['dataSharingAgreement'], veramo: Veramo<BaseWalletModel>, signer: 'provider' | 'consumer'): Promise<Error[]> {
  const errors: Error[] = []

  const { signatures, ...expectedPayloadClaims } = agreement
  let verifiedSignature: WalletPaths.DidJwtVerify.Responses.$200
  let expectedSigner: string
  if (signer === 'provider') {
    expectedSigner = expectedPayloadClaims.parties.providerDid
    verifiedSignature = await didJwtVerify(signatures.providerSignature, veramo, expectedPayloadClaims)
  } else {
    expectedSigner = expectedPayloadClaims.parties.consumerDid
    verifiedSignature = await didJwtVerify(signatures.consumerSignature, veramo, expectedPayloadClaims)
  }

  if (verifiedSignature.verification === 'success') {
    if (verifiedSignature.decodedJwt?.iss !== expectedSigner) {
      errors.push(new Error(`Signing DID does not match expected signer: ${verifiedSignature.decodedJwt?.iss as string ?? 'undefined'} != ${expectedSigner}`))
    }
  } else {
    errors.push(new Error(verifiedSignature.error))
  }

  return errors
}
