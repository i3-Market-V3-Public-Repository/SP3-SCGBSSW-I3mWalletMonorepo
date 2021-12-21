import pbkdf2Hmac from 'pbkdf2-hmac'
import * as objectSha from 'object-sha'
import { bufferUtils, format, Cipher } from '../internal'
import { Identity } from './state'

const deriveKey = async (
  from: string, to: string, secret: Uint8Array
): Promise<Uint8Array> => {
  // Prepare data
  const salt = new Uint8Array(16)
  const pbkdf2Input = new Uint8Array(32 * 3)
  const fromBuffer = format.hex2U8Arr(from)
  const toBuffer = format.hex2U8Arr(to)

  // Prepare input
  bufferUtils.insertBytes(secret, pbkdf2Input, 0, 0, 32)
  bufferUtils.insertBytes(fromBuffer, pbkdf2Input, 0, 32, 32)
  bufferUtils.insertBytes(toBuffer, pbkdf2Input, 0, 32 * 2, 32)

  const derivatedSecret = await pbkdf2Hmac(pbkdf2Input, salt, 1, 32)
  return new Uint8Array(derivatedSecret)
}

export class MasterKey {
  protected cipher: Cipher
  protected decipher: Cipher

  constructor (
    public readonly port: number,
    public readonly from: Identity,
    public readonly to: Identity,
    public readonly na: Uint8Array,
    public readonly nb: Uint8Array,
    protected secret: Uint8Array,
    encryptKey: Uint8Array,
    decryptKey: Uint8Array
  ) {
    this.cipher = new Cipher('aes-256-gcm', encryptKey)
    this.decipher = new Cipher('aes-256-gcm', decryptKey)
  }

  async encrypt (message: Uint8Array): Promise<Uint8Array> {
    return await this.cipher.encrypt(message)
  }

  async decrypt (ciphertext: Uint8Array): Promise<Uint8Array> {
    return await this.decipher.decrypt(ciphertext)
  }

  toJSON (): any {
    return {
      from: this.from,
      to: this.to,
      port: this.port,
      na: format.u8Arr2Base64(this.na),
      nb: format.u8Arr2Base64(this.nb),
      secret: format.u8Arr2Base64(this.secret)
    }
  }

  async fromHash (): Promise<string> {
    return await objectSha.digest(this.from)
  }

  async toHash (): Promise<string> {
    return await objectSha.digest(this.to)
  }

  static async fromSecret (port: number, from: Identity, to: Identity, na: Uint8Array, nb: Uint8Array, secret: Uint8Array): Promise<MasterKey> {
    const fromHash = await objectSha.digest(from)
    const toHash = await objectSha.digest(to)

    const encryptKey = await deriveKey(fromHash, toHash, secret)
    const decryptKey = await deriveKey(toHash, fromHash, secret)

    return new MasterKey(port, from, to, na, nb, secret, encryptKey, decryptKey)
  }

  static async fromJSON (data: any): Promise<MasterKey> {
    const na = format.base642U8Arr(data.na)
    const nb = format.base642U8Arr(data.nb)
    const secret = format.base642U8Arr(data.secret)

    return await this.fromSecret(data.port, data.from, data.to, na, nb, secret)
  }
}
