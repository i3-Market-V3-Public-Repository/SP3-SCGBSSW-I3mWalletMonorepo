import { mkdir, rm } from 'fs/promises'
import { EventEmitter } from 'events'
// TODO: Use atomically
// import { readFileSync, writeFileSync } from 'atomically'
import { writeFileSync, readFileSync } from 'fs'
import _ from 'lodash'
import { BinaryLike, createCipheriv, createDecipheriv, createSecretKey, KeyObject, randomBytes, scrypt } from 'crypto'
import { dirname } from 'path'
import { Store } from '../../app'

/**
 * A class that implements a storage for the wallet in a single file. The server wallet uses a file as storage.
 *
 * `filepath` is the path to the Wallet's storage file. If you are using a container it should be a path to a file that persists (like one in a volume)
 *
 * The wallet's storage-file can be encrypted for added security.
 */
export class FileStore<T extends Record<string, any> = Record<string, unknown>> extends EventEmitter implements Store<T> {
  filepath: string
  private key!: KeyObject
  private readonly _password?: string
  private _passwordSalt?: Buffer
  initialized: Promise<void>
  defaultModel: T

  /**
   *
   * @param filepath an absolute path to the file that will be used to store wallet data
   * @param keyObject a key object holding a 32 bytes symmetric key to use for encryption/decryption of the storage
   */
  constructor (filepath: string, keyObject?: KeyObject, defaultModel?: T)
  /**
   *
   * @param filepath an absolute path to the file that will be used to store wallet data
   * @param password if provided a key will be derived from the password and the store file will be encrypted
   *
   * @deprecated you should consider passing a more secure KeyObject derived from your password
   */
  constructor (filepath: string, password?: string, defaultModel?: T)
  constructor (filepath: string, keyObjectOrPassword?: KeyObject | string, defaultModel?: T) {
    super()
    const isNode = typeof process !== 'undefined' && process.versions != null && process.versions.node != null
    if (!isNode) {
      throw new Error('FileStore can only be instantiated from Node.js')
    }
    this.filepath = filepath

    if (keyObjectOrPassword instanceof KeyObject) {
      this.key = keyObjectOrPassword
    } else if (typeof keyObjectOrPassword === 'string') {
      this._password = keyObjectOrPassword
    }

    this.defaultModel = defaultModel ?? {} as any
    this.initialized = this.init()
  }

  on (eventName: 'changed', listener: (changedAt: number) => void): this
  on (eventName: 'cleared', listener: (changedAt: number) => void): this
  on (eventName: string | symbol, listener: (...args: any[]) => void): this
  on (eventName: string | symbol, listener: (...args: any[]) => void): this {
    return super.on(eventName, listener)
  }

  emit (eventName: 'changed', changedAt: number): boolean
  emit (eventName: 'cleared', changedAt: number): boolean
  emit (eventName: string | symbol, ...args: any[]): boolean
  emit (eventName: string | symbol, ...args: any[]): boolean {
    return super.emit(eventName, ...args)
  }

  private async init (): Promise<void> {
    await mkdir(dirname(this.filepath), { recursive: true }).catch()

    if (this._password !== undefined) {
      await this.deriveKey(this._password)
    }
    const model = await this.getModel()
    await this.setModel(model)
  }

  async deriveKey (password: string, salt?: Buffer): Promise<void> {
    this._passwordSalt = salt ?? randomBytes(64)
    // derive encryption key
    this.key = await deriveKey(password, {
      alg: 'scrypt',
      derivedKeyLength: 32,
      salt: this._passwordSalt
    })
  }

  private async getModel (): Promise<T> {
    let model = _.cloneDeep(this.defaultModel)
    try {
      const fileBuf = readFileSync(this.filepath)
      if (this.key === undefined) {
        model = JSON.parse(fileBuf.toString('utf8'))
      } else {
        model = await this.decryptModel(fileBuf)
      }
    } catch (error: unknown) {
      if ((error as any)?.code !== 'ENOENT') {
        throw error
      }
    }
    return model
  }

  private async setModel (model: T): Promise<void> {
    if (this.key === undefined) {
      writeFileSync(this.filepath, JSON.stringify(model), { encoding: 'utf8' })
    } else {
      writeFileSync(this.filepath, await this.encryptModel(model))
    }
  }

  private async encryptModel (model: T): Promise<Buffer> {
    if (this._password === undefined && this.key === undefined) {
      throw new Error('For the store to be encrypted you must provide a key/password')
    }

    // random initialization vector
    const iv = randomBytes(16)

    // AES 256 GCM Mode
    const cipher = createCipheriv('aes-256-gcm', this.key, iv)

    // encrypt the given text
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(model), 'utf8'), cipher.final()])

    // extract the auth tag
    const tag = cipher.getAuthTag()

    // generate output
    if (this._passwordSalt !== undefined) {
      return Buffer.concat([this._passwordSalt, iv, tag, encrypted])
    }
    return Buffer.concat([iv, tag, encrypted])
  }

  private async decryptModel (encryptedModel: ArrayBufferLike): Promise<T> {
    if (this._password === undefined && this.key === undefined) {
      throw new Error('For the store to be encrypted you must provide a key/password')
    }

    // extract all parts.
    const buf = Buffer.from(encryptedModel)

    let iv: Buffer
    let tag: Buffer
    let ciphertext: Buffer
    if (this._password !== undefined) {
      const salt = buf.subarray(0, 64)
      if (salt.compare(this._passwordSalt!) !== 0) { // eslint-disable-line @typescript-eslint/no-non-null-assertion
        await this.deriveKey(this._password, salt)
      }
      iv = buf.subarray(64, 80)
      tag = buf.subarray(80, 96)
      ciphertext = buf.subarray(96)
    } else {
      iv = buf.subarray(0, 16)
      tag = buf.subarray(16, 32)
      ciphertext = buf.subarray(32)
    }

    // AES 256 GCM Mode
    const decipher = createDecipheriv('aes-256-gcm', this.key, iv)
    decipher.setAuthTag(tag)

    // decrypt, pass to JSON string, parse
    return JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8'))
  }

  async get (key: any, defaultValue?: any): Promise<any> {
    await this.initialized

    const model = await this.getModel()
    return _.get(model, key, defaultValue)
  }

  async set (keyOrStore: any, value?: any): Promise<void> {
    await this.initialized

    const model = await this.getModel()
    if (value === undefined) {
      Object.assign(model, keyOrStore)
    } else {
      _.set(model, keyOrStore, value)
    }

    await this.setModel(model)
    this.emit('changed', Date.now())
  }

  async has (key: any): Promise<boolean> {
    await this.initialized

    const model = await this.getModel()
    return _.has(model, key)
  }

  async delete (key: any): Promise<void> {
    await this.initialized

    let model = await this.getModel()
    model = _.omit(model, key) as any
    await this.setModel(model)
    this.emit('changed', Date.now())
  }

  async clear (): Promise<void> {
    await this.initialized
    this.emit('cleared', Date.now())

    await rm(this.filepath)
  }

  public async getStore (): Promise<T> {
    await this.initialized

    return await this.getModel()
  }

  public getPath (): string {
    return this.filepath
  }
}

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
