import { generateKeys } from '@i3m/non-repudiation-library'
import { OpenApiComponents } from '../../types/openapi'

export interface JwkPair {
  publicJwk: OpenApiComponents.Schemas.JwkEcPublicKey
  privateJwk: OpenApiComponents.Schemas.JwkEcPrivateKey
}

async function createJwks (): Promise<JwkPair> {
  const keypair = await generateKeys('ES256')
  return {
    publicJwk: keypair.publicJwk as OpenApiComponents.Schemas.JwkEcPublicKey,
    privateJwk: keypair.privateJwk as OpenApiComponents.Schemas.JwkEcPrivateKey
  }
}

export const jwksPromise = createJwks()
