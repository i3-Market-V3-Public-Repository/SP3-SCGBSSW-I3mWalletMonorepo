import crypto from 'crypto'
import { BaseECDH } from '../types'

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
