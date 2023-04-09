import { jwsDecode } from '../crypto/index.js'
import { DecodedProof, JWK, ResolutionPayload } from '../types.js'

export async function verifyResolution<T extends ResolutionPayload> (resolution: string, pubJwk?: JWK): Promise<DecodedProof<T>> {
  return await jwsDecode<T>(resolution, pubJwk ?? ((header, payload) => {
    return JSON.parse(payload.iss)
  }))
}
