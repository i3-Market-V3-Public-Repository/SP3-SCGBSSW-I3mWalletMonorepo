import crypto from 'crypto'
import { BaseDigest, HashAlgorithms } from '../types'

class NodeDigest extends BaseDigest {
  async digest (algorithm: HashAlgorithms, input: Uint8Array): Promise<Uint8Array> {
    const hash = crypto.createHash(algorithm)
    const buffer = hash.update(input).digest()

    return new Uint8Array(buffer.buffer)
  }
}
export const digest = new NodeDigest()
