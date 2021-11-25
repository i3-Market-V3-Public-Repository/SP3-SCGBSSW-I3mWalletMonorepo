import { format } from '../../internal'
import { BaseDigest, BaseECDH, BaseRandom, HashAlgorithms, NODE_TO_BROWSER_HASH_ALGORITHMS } from '../types'

class BrowserRandom extends BaseRandom {
  async randomFill (buffer: Uint8Array, start: number, size: number): Promise<void> {
    const newBuffer = new Uint8Array(size)
    crypto.getRandomValues(newBuffer)
    for (let i = 0; i < size; i++) {
      buffer[start + i] = newBuffer[i]
    }
  }
}
export const random: BaseRandom = new BrowserRandom()

export class ECDH extends BaseECDH {
  keys?: CryptoKeyPair

  async generateKeys (): Promise<void> {
    this.keys = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits'])
  }

  async getPublicKey (): Promise<string> {
    if (this.keys === undefined || this.keys.publicKey === undefined) {
      throw new Error('keys must be initialized fist')
    }

    const publicKey = await crypto.subtle.exportKey('raw', this.keys.publicKey)
    return format.u8Arr2hex(new Uint8Array(publicKey))
  }

  async deriveBits (publicKeyHex: string): Promise<Uint8Array> {
    if (this.keys === undefined || this.keys.privateKey === undefined) {
      throw new Error('keys must be generated first')
    }

    const publicKeyBuffer = format.hex2U8Arr(publicKeyHex)
    const publicKey = await crypto.subtle.importKey(
      'raw', publicKeyBuffer, {
        name: 'ECDH',
        namedCurve: 'P-256'
      }, true, []
    )

    const secret = await crypto.subtle.deriveBits({
      name: 'ECDH',
      public: publicKey
    }, this.keys.privateKey, 256)

    return new Uint8Array(secret)
  }
}

class BrowserDigest extends BaseDigest {
  async digest (algorithm: HashAlgorithms, input: Uint8Array): Promise<Uint8Array> {
    const browserAlgorithm = NODE_TO_BROWSER_HASH_ALGORITHMS[algorithm]
    const buffer = await crypto.subtle.digest(browserAlgorithm, input)

    return new Uint8Array(buffer)
  }
}
export const digest = new BrowserDigest()
