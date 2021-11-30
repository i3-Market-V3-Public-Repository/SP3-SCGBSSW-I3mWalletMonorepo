import { format } from '../../internal'
import { BaseECDH } from '../types'

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
    return format.u8Arr2Hex(new Uint8Array(publicKey))
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
