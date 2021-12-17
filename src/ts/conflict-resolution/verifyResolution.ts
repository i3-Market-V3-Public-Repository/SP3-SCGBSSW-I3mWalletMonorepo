import { jwsDecode } from '../crypto'
import { DecodedProof, JWK, ResolutionPayload } from '../types'

export async function verifyResolution<T extends ResolutionPayload> (resolution: string, pubJwk?: JWK): Promise<DecodedProof<T>> {
  return await jwsDecode<T>(resolution, pubJwk ?? ((header, payload) => {
    return JSON.parse(payload.iss)
  }))
}
