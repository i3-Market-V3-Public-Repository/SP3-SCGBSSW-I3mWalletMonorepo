import _ from 'lodash'
import { Store } from '../../app'
import { readFile, writeFile, rm, mkdir } from 'fs/promises'
import * as crypto from 'crypto'
import { dirname } from 'path'

/**
 * A class that implements a storage for the wallet in a single file. The server wallet uses a file as storage.
 *
 * `filepath` is the path to the Wallet's storage file. If you are using a container it should be a path to a file that persists (like one in a volume)
 *
 * The wallet's storage-file can be encrypted for added security by passing an optional `password`.
 */
export class FileStore<T extends Record<string, any> = Record<string, unknown>> implements Store<T> {
  filepath: string
  password?: string
  initialized: Promise<void>
  defaultModel: T

  /**
   *
   * @param filepath an absolute path to the file that will be used to store wallet data
   * @param password if provided a key will be derived from the password and the store file will be encrypted
   */
  constructor (filepath: string, password?: string, defaultModel?: T) {
    const isNode = typeof process !== 'undefined' && process.versions != null && process.versions.node != null
    if (!isNode) {
      throw new Error('FileStore can only be instantiated from Node.js')
    }
    this.filepath = filepath
    this.password = password
    this.defaultModel = defaultModel ?? {} as any
    this.initialized = this.init()
  }

  private kdf (password: string, salt: crypto.BinaryLike): Buffer {
    return crypto.scryptSync(password, salt, 32)
  }

  private async init (): Promise<void> {
    await mkdir(dirname(this.filepath), { recursive: true }).catch()
    const model = await this.getModel()
    await this.setModel(model)
  }

  private async getModel (): Promise<T> {
    let model = _.cloneDeep(this.defaultModel)
    try {
      const fileBuf = await readFile(this.filepath)
      if (this.password === undefined) {
        model = JSON.parse(fileBuf.toString('utf8'))
      } else {
        model = await this.decryptModel(fileBuf)
      }
    } catch (error) {}
    return model
  }

  private async setModel (model: T): Promise<void> {
    if (this.password === undefined) {
      await writeFile(this.filepath, JSON.stringify(model), { encoding: 'utf8' })
    } else {
      await writeFile(this.filepath, await this.encryptModel(model))
    }
  }

  private async encryptModel (model: T): Promise<Buffer> {
    if (this.password === undefined) {
      throw new Error('For the store to be encrypted you must provide a password')
    }

    // random initialization vector
    const iv = crypto.randomBytes(16)

    // random salt
    const salt = crypto.randomBytes(64)

    // derive encryption key
    const key = this.kdf(this.password, salt)

    // AES 256 GCM Mode
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)

    // encrypt the given text
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(model), 'utf8'), cipher.final()])

    // extract the auth tag
    const tag = cipher.getAuthTag()

    // generate output
    return Buffer.concat([salt, iv, tag, encrypted])
  }

  private async decryptModel (encryptedModel: ArrayBufferLike): Promise<T> {
    if (this.password === undefined) {
      throw new Error('For the store to be encrypted you must provide a password')
    }

    // extract all parts
    const buf = Buffer.from(encryptedModel)
    const salt = buf.subarray(0, 64)
    const iv = buf.subarray(64, 80)
    const tag = buf.subarray(80, 96)
    const ciphertext = buf.subarray(96)

    // derive encryption key
    const key = this.kdf(this.password, salt)

    // AES 256 GCM Mode
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
    decipher.setAuthTag(tag)

    // decrypt, pass to JSON string, parse
    const decrypted = JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8'))

    return decrypted
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
  }

  async has<Key extends 'accounts'>(key: Key): Promise<boolean> {
    await this.initialized

    const model = await this.getModel()
    return _.has(model, key)
  }

  async delete<Key extends 'accounts'>(key: Key): Promise<void> {
    await this.initialized

    let model = await this.getModel()
    model = _.omit(model, key) as any
    await this.setModel(model)
  }

  async clear (): Promise<void> {
    await this.initialized

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
