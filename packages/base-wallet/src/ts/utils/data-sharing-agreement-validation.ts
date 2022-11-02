import { parseJwk } from '@i3m/non-repudiation-library'
import spec from '@i3m/wallet-desktop-openapi/openapi_dereferenced.json'
import { WalletPaths, WalletComponents } from '@i3m/wallet-desktop-openapi/types'
import { validate, Schema } from 'jsonschema'
import { BaseWalletModel, ContractResource } from '../app'
import { didJwtVerify } from '../utils/did-jwt-verify'
import Veramo from '../veramo'
import { parseAddress } from './parseAddress'

export async function validateDataSharingAgreeementSchema (agreement: WalletComponents.Schemas.DataSharingAgreement): Promise<Error[]> {
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

export async function validateDataExchangeAgreement (dea: WalletComponents.Schemas.DataExchangeAgreement): Promise<Error[]> {
  const errors: Error[] = []
  try {
    if (dea.orig !== await parseJwk(JSON.parse(dea.orig), true)) {
      errors.push(new Error('orig is not a valid stringified JWK with the claims sorted alphabetically: ' + dea.orig))
    }
  } catch (error) {
    errors.push(new Error('orig is not a valid stringified JWK with the claims sorted alphabetically'))
  }
  try {
    if (dea.dest !== await parseJwk(JSON.parse(dea.dest), true)) {
      errors.push(new Error('dest is not a valid stringified JWK with the claims sorted alphabetically: ' + dea.dest))
    }
  } catch (error) {
    errors.push(new Error('dest is not a valid stringified JWK with the claims sorted alphabetically'))
  }
  try {
    if (dea.ledgerContractAddress !== parseAddress(dea.ledgerContractAddress)) {
      errors.push(new Error('ledgerContractAddress is not a valid EIP-55 ethereum address: ' + dea.ledgerContractAddress))
    }
  } catch (error) {
    errors.push(new Error('ledgerContractAddress is not a valid EIP-55 ethereum address'))
  }
  try {
    if (dea.ledgerSignerAddress !== parseAddress(dea.ledgerSignerAddress)) {
      errors.push(new Error('ledgerSignerAddress is not a valid EIP-55 ethereum address: ' + dea.ledgerSignerAddress))
    }
  } catch (error) {
    errors.push(new Error('ledgerSignerAddress is not a valid EIP-55 ethereum address'))
  }
  return errors
}

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
