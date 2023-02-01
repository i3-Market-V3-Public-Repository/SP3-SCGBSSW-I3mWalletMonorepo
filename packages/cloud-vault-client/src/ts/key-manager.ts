import { BinaryLike, createSecretKey, KeyObject, scrypt } from 'node:crypto'

export interface ScryptOptions {
  N?: number
  r?: number
  p?: number
  maxmem?: number
}

export interface KdfOptions {
  alg: 'scrypt'
  derivedKeyLength: number // in octets
  salt: BinaryLike
  algOptions?: ScryptOptions
}

export interface DerivationOptions {
  master: KdfOptions
  auth: KdfOptions
  enc: KdfOptions
}

export class KeyManager {
  private _encKey!: KeyObject
  private _authKey!: KeyObject
  derivationOptions: DerivationOptions
  initialized: Promise<void>

  constructor (password: BinaryLike, opts: DerivationOptions) {
    this.derivationOptions = opts
    this.initialized = this.init(password)
  }

  private async init (password: BinaryLike): Promise<void> {
    const masterKey = await deriveKey(password, this.derivationOptions.master, true)

    const [authKey, encKey] = await Promise.all([
      deriveKey(masterKey, this.derivationOptions.auth),
      deriveKey(masterKey, this.derivationOptions.enc)
    ])

    this._authKey = authKey
    this._encKey = encKey
  }

  async getAuthKey (): Promise<string> {
    await this.initialized
    return this._authKey.export().toString('base64url')
  }

  async getEncKey (): Promise<KeyObject> {
    await this.initialized
    return this._encKey
  }
}

export async function deriveKey (password: BinaryLike, opts: KdfOptions, returnBuffer?: false): Promise<KeyObject>
export async function deriveKey (password: BinaryLike, opts: KdfOptions, returnBuffer: true): Promise<Buffer>
export async function deriveKey<T extends Buffer | KeyObject> (password: BinaryLike, opts: KdfOptions, returnBuffer = false): Promise<T> {
  let scryptOptions: ScryptOptions = {}
  if (opts.algOptions !== undefined) {
    scryptOptions = {
      N: 16384,
      r: 8,
      p: 1,
      ...opts.algOptions
    }
    scryptOptions.maxmem = 256 * scryptOptions.N! * scryptOptions.r! // eslint-disable-line @typescript-eslint/no-non-null-assertion
  }
  const keyPromise: Promise<any> = new Promise((resolve, reject) => {
    scrypt(password, opts.salt, opts.derivedKeyLength, scryptOptions, (err, key) => {
      if (err !== null) reject(err)
      resolve(returnBuffer ? key : createSecretKey(key))
    })
  })
  return await keyPromise
}
