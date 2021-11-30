import crypto from 'crypto'
import { bufferUtils } from '../../internal'
import { BaseCipher } from '../types'
import { random } from './random'

export class Cipher extends BaseCipher {
  async encrypt (payload: Uint8Array): Promise<Uint8Array> {
    const iv = new Uint8Array(12)
    await random.randomFill(iv, 0, iv.length)
    const cryptoKey = crypto.createSecretKey(this.key)
    const cipher = crypto.createCipheriv(this.algorithm, cryptoKey, iv)

    const buffers: Uint8Array[] = []
    buffers.push(iv)
    buffers.push(cipher.update(payload))
    buffers.push(cipher.final())
    buffers.push(cipher.getAuthTag())

    return bufferUtils.join(...buffers)
  }

  async decrypt (cryptosecuence: Uint8Array): Promise<Uint8Array> {
    const sizes: number[] = []
    switch (this.algorithm) {
      case 'aes-256-gcm':
        sizes[0] = 12 // IV Size
        sizes[2] = 16 // AuthTag size
        break
    }
    sizes[1] = cryptosecuence.length - sizes[0] - (sizes[2] ?? 0)
    const [iv, ciphertext, authTag] = bufferUtils.split(cryptosecuence, ...sizes)

    const cryptoKey = crypto.createSecretKey(this.key)
    const decipher = crypto.createDecipheriv(this.algorithm, cryptoKey, iv)
    if (authTag !== undefined) {
      decipher.setAuthTag(authTag)
    }

    const buffers: Uint8Array[] = []
    buffers.push(decipher.update(ciphertext))
    buffers.push(decipher.final())
    return bufferUtils.join(...buffers)
  }
}
