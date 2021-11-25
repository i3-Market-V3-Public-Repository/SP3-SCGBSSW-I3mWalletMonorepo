import crypto from 'crypto'
import { BaseDigest, BaseECDH, BaseRandom, HashAlgorithms } from '../types'

class NodeRandom extends BaseRandom {
  async randomFill (buffer: Uint8Array, start: number, size: number): Promise<void> {
    return await new Promise<void>(resolve => {
      crypto.randomFill(buffer, start, size, () => {
        resolve()
      })
    })
  }
}
export const random: BaseRandom = new NodeRandom()

export class ECDH extends BaseECDH {
  ecdh: crypto.ECDH
  constructor () {
    super()
    this.ecdh = crypto.createECDH('prime256v1')
  }

  async generateKeys (): Promise<void> {
    // FIXME: PSEUDO RANDOM! DANGER!! OR NOT???
    this.ecdh.generateKeys()
  }

  async getPublicKey (): Promise<string> {
    return this.ecdh.getPublicKey('hex')
  }

  async deriveBits (publicKeyHex: string): Promise<Uint8Array> {
    const key = this.ecdh.computeSecret(publicKeyHex, 'hex')
    return new Uint8Array(key)
  }
}

class NodeDigest extends BaseDigest {
  async digest (algorithm: HashAlgorithms, input: Uint8Array): Promise<Uint8Array> {
    const hash = crypto.createHash(algorithm)
    const buffer = hash.update(input).digest()

    return new Uint8Array(buffer.buffer)
  }
}
export const digest = new NodeDigest()
