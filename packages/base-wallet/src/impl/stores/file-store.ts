import _ from 'lodash'
import { Store, BaseWalletModel } from '../../app'
import { readFile, writeFile, rm, mkdir } from 'fs/promises'
import * as crypto from 'crypto'
import { dirname } from 'path'

/**
 * A class that implements a storage in a file to be used by a wallet
 */
export class FileStore implements Store<BaseWalletModel> {
  filepath: string
  password?: string

  /**
   *
   * @param filepath an absolute path to the file that will be used to store wallet data
   * @param password if provided a key will be derived from the password and the store file will be encrypted
   */
  constructor (filepath: string, password?: string) {
    const isNode = typeof process !== 'undefined' && process.versions != null && process.versions.node != null
    if (!isNode) {
      throw new Error('FileStore can only be instantiated from Node.js')
    }
    this.filepath = filepath
    this.password = password
    this.init().catch(error => {
      throw error
    })
  }

  private kdf (password: string, salt: crypto.BinaryLike): Buffer {
    return crypto.scryptSync(password, salt, 32)
  }

  private async init (): Promise<void> {
    await mkdir(dirname(this.filepath), { recursive: true }).catch()
    const model = await this.getModel()
    await this.setModel(model)
  }

  private defaultModel (): BaseWalletModel {
    return {
      resources: {},
      identities: {}
    }
  }

  private async getModel (): Promise<BaseWalletModel> {
    let model = this.defaultModel()
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

  private async setModel (model: BaseWalletModel): Promise<void> {
    if (this.password === undefined) {
      await writeFile(this.filepath, JSON.stringify(model), { encoding: 'utf8' })
    } else {
      await writeFile(this.filepath, await this.encryptModel(model))
    }
  }

  private async encryptModel (model: BaseWalletModel): Promise<Buffer> {
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

  private async decryptModel (encryptedModel: ArrayBufferLike): Promise<BaseWalletModel> {
    if (this.password === undefined) {
      throw new Error('For the store to be encrypted you must provide a password')
    }

    // extract all parts
    const buf = Buffer.from(encryptedModel)
    const salt = buf.slice(0, 64)
    const iv = buf.slice(64, 80)
    const tag = buf.slice(80, 96)
    const ciphertext = buf.slice(96)

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
    await this.init()
    const model = await this.getModel()
    return _.get(model, key, defaultValue)
  }

  async set (key: string, value: unknown): Promise<void>
  async set (key: any, value: any): Promise<void> {
    await this.init()
    const model = await this.getModel()
    _.set(model, key, value)
    await this.setModel(model)
  }

  async has<Key extends 'accounts'>(key: Key): Promise<boolean> {
    await this.init()
    const model = await this.getModel()
    return _.has(model, key)
  }

  async delete<Key extends 'accounts'>(key: Key): Promise<void> {
    await this.init()
    let model = await this.getModel()
    model = _.omit(model, key) as any
    await this.setModel(model)
  }

  async clear (): Promise<void> {
    await this.init()
    await rm(this.filepath)
  }
}
