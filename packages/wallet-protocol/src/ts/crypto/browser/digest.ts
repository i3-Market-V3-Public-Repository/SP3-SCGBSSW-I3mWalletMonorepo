import { BaseDigest, HashAlgorithms } from '../types'

const NODE_TO_BROWSER_HASH_ALGORITHMS: Record<HashAlgorithms, string> = {
  sha256: 'SHA-256'
}

class BrowserDigest extends BaseDigest {
  async digest (algorithm: HashAlgorithms, input: Uint8Array): Promise<Uint8Array> {
    const browserAlgorithm = NODE_TO_BROWSER_HASH_ALGORITHMS[algorithm]
    const buffer = await crypto.subtle.digest(browserAlgorithm, input)

    return new Uint8Array(buffer)
  }
}
export const digest = new BrowserDigest()
