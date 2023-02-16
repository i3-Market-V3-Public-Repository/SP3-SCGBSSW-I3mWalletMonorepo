import { verifyJWT } from 'did-jwt'
import { Veramo } from '../veramo'
import { decodeJWS } from './jws'
import { WalletPaths } from '@i3m/wallet-desktop-openapi/types'
import _ from 'lodash'

// type Dict<T> = T & {
//   [key: string]: any | undefined
// }

/*
 * Compare two objects by reducing an array of keys in obj1, having the
 * keys in obj2 as the intial value of the result. Key points:
 *
 * - All keys of obj2 are initially in the result.
 *
 * - If the loop finds a key (from obj1, remember) not in obj2, it adds
 *   it to the result.
 *
 * - If the loop finds a key that are both in obj1 and obj2, it compares
 *   the value. If it's the same value, the key is removed from the result.
 */
function getObjectDiff (obj1: any, obj2: any): string[] {
  const diff = Object.keys(obj1).reduce((result, key) => {
    if (!Object.prototype.hasOwnProperty.call(obj2, key)) {
      result.push(key)
    } else if (_.isEqual(obj1[key], obj2[key])) {
      const resultKeyIndex = result.indexOf(key)
      result.splice(resultKeyIndex, 1)
    }
    return result
  }, Object.keys(obj2))
  return diff
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
    const expectedPayloadMerged = _.cloneDeep(expectedPayloadClaims)
    _.defaultsDeep(expectedPayloadMerged, payload)

    const diffs = getObjectDiff(payload, expectedPayloadMerged)
    if (diffs.length > 0) {
      return {
        verification: 'failed',
        error: 'The following top-level properties are missing or different: ' + diffs.join(', '),
        decodedJwt
      }
    }
    // const isExpectedPayload = _.isEqual(expectedPayloadMerged, payload)

    // if (!isExpectedPayload) {
    //   return {
    //     verification: 'failed',
    //     error: 'some or all the expected payload claims are not as expected',
    //     decodedJwt
    //   }
    // }
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
