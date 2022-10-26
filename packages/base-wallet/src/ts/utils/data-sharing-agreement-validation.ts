import spec from '@i3m/wallet-desktop-openapi/openapi_dereferenced.json'
import { WalletPaths } from '@i3m/wallet-desktop-openapi/types'
import { validate, Schema } from 'jsonschema'
import { BaseWalletModel, ContractResource } from '../app'
import { didJwtVerify } from '../utils/did-jwt-verify'
import Veramo from '../veramo'

export async function validateDataSharingAgreeementSchema (agreement: ContractResource['resource']): Promise<Error[]> {
  const errors: Error[] = []

  const dataSharingAgreementSchema = spec.components.schemas.dataSharingAgreement
  const validation = validate(agreement, dataSharingAgreementSchema as Schema)
  if (!validation.valid) {
    validation.errors.forEach(error => {
      errors.push(new Error(`[${error.property}]: ${error.message}`))
    })
  }
  return errors
}

export async function verifyDataSharingAgreementSignature (agreement: ContractResource['resource'], veramo: Veramo<BaseWalletModel>, signer: 'provider' | 'consumer'): Promise<Error[]> {
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
      errors.push(new Error(`Signing DID does not match expected signer ${expectedSigner}`))
    }
  } else {
    errors.push(new Error(verifiedSignature.error))
  }

  return errors
}
