import { hashable } from 'object-sha'
import { verifyJWT } from 'did-jwt'
import Veramo, {} from '../veramo'
import { decodeJWS } from './jws'
import { WalletPaths } from '@i3m/wallet-desktop-openapi/types'

type Dict<T> = T & {
  [key: string]: any | undefined
}

/**
   * Verifies a JWT resolving the public key from the signer DID (no other kind of signer supported) and optionally check values for expected payload claims.
   *
   * The Wallet only supports the 'ES256K1' algorithm.
   *
   * Useful to verify JWT created by another wallet instance.
   * @param requestBody
   * @returns
   */
export async function didJwtVerify (jwt: string, veramo: Veramo, expectedPayloadClaims?: any): Promise<WalletPaths.DidJwtVerify.Responses.$200> {
  let decodedJwt
  try {
    decodedJwt = decodeJWS(jwt)
  } catch (error) {
    return {
      verification: 'failed',
      error: 'Invalid JWT format'
    }
  }

  const payload = decodedJwt.payload

  if (expectedPayloadClaims !== undefined) {
    const expectedClaimsDict: Dict<typeof expectedPayloadClaims> = expectedPayloadClaims

    let error: string | undefined
    for (const key in expectedClaimsDict) {
      if (payload[key] === undefined) error = `Expected key '${key}' not found in payload`
      if (expectedClaimsDict[key] !== '' && hashable(expectedClaimsDict[key] as object) !== hashable(payload[key] as object)) {
        error = `Payload's ${key}: ${JSON.stringify(payload[key], undefined, 2)} does not meet provided value ${JSON.stringify(expectedClaimsDict[key], undefined, 2)}`
      }
    }
    if (error !== undefined) {
      return {
        verification: 'failed',
        error,
        decodedJwt
      }
    }
  }
  const resolver = { resolve: async (didUrl: string) => await veramo.agent.resolveDid({ didUrl }) }
  try {
    const verifiedJWT = await verifyJWT(jwt, { resolver })
    return {
      verification: 'success',
      decodedJwt: verifiedJWT.payload
    }
  } catch (error) {
    if (error instanceof Error) {
      return {
        verification: 'failed',
        error: error.message,
        decodedJwt
      }
    } else throw new Error('unknown error during verification')
  }
}
