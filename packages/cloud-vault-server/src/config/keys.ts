import { generateKeys } from '@i3m/non-repudiation-library'
import { OpenApiComponents } from '../../types/openapi.js'

export interface JwkPair {
  publicJwk: OpenApiComponents.Schemas.JwkEcPublicKey
  privateJwk: OpenApiComponents.Schemas.JwkEcPublicKey & { d: string }
}

async function createJwks (): Promise<JwkPair> {
  const keypair = await generateKeys('ES256')
  return {
    publicJwk: keypair.publicJwk as OpenApiComponents.Schemas.JwkEcPublicKey,
    privateJwk: keypair.privateJwk as OpenApiComponents.Schemas.JwkEcPublicKey & { d: string }
  }
}

export const jwksPromise = createJwks()
