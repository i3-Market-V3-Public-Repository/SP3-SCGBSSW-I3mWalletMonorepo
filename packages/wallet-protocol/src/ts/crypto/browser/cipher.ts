import { bufferUtils } from '../../internal'
import { BaseCipher, CipherAlgorithms } from '../types'
import { random } from './random'

interface BrowserCipherAlgorithm {
  name: string
  tagLength?: number
}

const NODE_TO_BROWSER_CIPHER_ALGORITHMS: Record<CipherAlgorithms, BrowserCipherAlgorithm> = {
  'aes-256-gcm': {
    name: 'AES-GCM',
    tagLength: 16 * 8
  }
}

export class Cipher extends BaseCipher {
  async encrypt (message: Uint8Array): Promise<Uint8Array> {
    const iv = new Uint8Array(12)
    await random.randomFill(iv, 0, iv.length)

    const alg = NODE_TO_BROWSER_CIPHER_ALGORITHMS[this.algorithm]
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      this.key,
      alg,
      false,
      ['encrypt']
    )

    const ciphertext = await crypto.subtle.encrypt({
      ...alg,
      iv
    }, cryptoKey, message)

    const buffers: Uint8Array[] = []
    buffers.push(iv)
    buffers.push(new Uint8Array(ciphertext))

    return bufferUtils.join(...buffers)
  }

  async decrypt (cryptosecuence: Uint8Array): Promise<Uint8Array> {
    const sizes: number[] = []
    switch (this.algorithm) {
      case 'aes-256-gcm':
        sizes[0] = 12 // IV Size
        break
    }
    sizes[1] = cryptosecuence.length - sizes[0]
    const [iv, ciphertext] = bufferUtils.split(cryptosecuence, ...sizes)

    const alg = NODE_TO_BROWSER_CIPHER_ALGORITHMS[this.algorithm]
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      this.key,
      alg,
      false,
      ['decrypt']
    )

    const message = await crypto.subtle.decrypt({
      ...alg,
      iv
    }, cryptoKey, ciphertext)

    return new Uint8Array(message)
  }
}
