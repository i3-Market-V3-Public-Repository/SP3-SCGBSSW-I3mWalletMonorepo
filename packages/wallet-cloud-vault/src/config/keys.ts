import { generateKeys, JwkPair } from '@i3m/non-repudiation-library'

async function createJwks (): Promise<JwkPair> {
  return await generateKeys('ES256')
}

export const jwksPromise = createJwks()
