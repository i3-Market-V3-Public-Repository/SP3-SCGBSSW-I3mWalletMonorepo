import { bufferUtils } from '../internal'

export class BaseECDH {
  async generateKeys (): Promise<void> {
    throw new Error('not implemented')
  }

  async getPublicKey (): Promise<string> {
    throw new Error('not implemented')
  }

  async deriveBits (publicKeyHex: string): Promise<Uint8Array> {
    throw new Error('not implemented')
  }
}

export class BaseRandom {
  async randomFill (buffer: Uint8Array, start: number, size: number): Promise<void> {
    throw new Error('not implemented')
  }

  async randomFillBits (buffer: Uint8Array, start: number, size: number): Promise<void> {
    const byteLen = Math.ceil(size / 8)
    const randomBytes = new Uint8Array(byteLen)
    await this.randomFill(randomBytes, 0, byteLen)
    bufferUtils.insertBits(randomBytes, buffer, 0, start, size)
  }
}

export type CipherAlgorithms = 'aes-256-gcm'
export class BaseCipher {
  constructor (
    public readonly algorithm: CipherAlgorithms,
    public readonly key: Uint8Array
  ) { }

  async encrypt (payload: Uint8Array): Promise<Uint8Array> {
    throw new Error('not implemented')
  }

  async decrypt (ciphertext: Uint8Array): Promise<Uint8Array> {
    throw new Error('not implemented')
  }
}

export type HashAlgorithms = 'sha256'

export class BaseDigest {
  async digest (algorithm: HashAlgorithms, input: Uint8Array): Promise<Uint8Array> {
    throw new Error('not implemented')
  }
}
