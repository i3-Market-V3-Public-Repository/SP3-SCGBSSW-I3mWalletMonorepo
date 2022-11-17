import * as crypto from 'crypto'
import { tmpdir } from 'os'
import { mkdir, readFile, writeFile, rm } from 'fs/promises'
import { dirname, join } from 'path'
import { SessionStorage, SessionFileStorageOptions } from '../types'

export class SessionFileStorage implements SessionStorage {
  filepath: string // a path to the file that will be used to store wallet session data
  password?: string // if provided a key will be derived from the password and the store file will be encrypted
  initialized: Promise<boolean>

  constructor (options?: SessionFileStorageOptions) {
    const isNode = typeof process !== 'undefined' && process.versions != null && process.versions.node != null
    if (!isNode) {
      throw new Error('FileStore can only be instantiated from Node.js')
    }
    this.filepath = (typeof options?.filepath === 'string' && options.filepath !== '') ? options.filepath : join(tmpdir(), 'i3m-wallet-session')
    this.password = options?.password
    this.initialized = new Promise((resolve, reject) => {
      this.init().then(() => {
        resolve(true)
      }).catch(reason => { reject(reason) })
    })
  }

  private async init (): Promise<void> {
    await mkdir(dirname(this.filepath), { recursive: true }).catch()
  }

  private kdf (password: string, salt: crypto.BinaryLike): Buffer {
    return crypto.scryptSync(password, salt, 32)
  }

  private async encryptJson (json: any): Promise<Buffer> {
    if (this.password === undefined) {
      throw new Error('For the store to be encrypted you must provide a password')
    }

    const plaintext = JSON.stringify(json)

    // random initialization vector
    const iv = crypto.randomBytes(16)

    // random salt
    const salt = crypto.randomBytes(64)

    // derive encryption key
    const key = this.kdf(this.password, salt)

    // AES 256 GCM Mode
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)

    // encrypt the given text
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])

    // extract the auth tag
    const tag = cipher.getAuthTag()

    // generate output
    return Buffer.concat([salt, iv, tag, encrypted])
  }

  private async decryptToJson (cryptogram: ArrayBufferLike): Promise<any> {
    if (this.password === undefined) {
      throw new Error('For the store to be encrypted you must provide a password')
    }

    // extract all parts
    const buf = Buffer.from(cryptogram)
    const salt = buf.slice(0, 64)
    const iv = buf.slice(64, 80)
    const tag = buf.slice(80, 96)
    const ciphertext = buf.slice(96)

    // derive encryption key
    const key = this.kdf(this.password, salt)

    // AES 256 GCM Mode
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
    decipher.setAuthTag(tag)

    // decrypt, pass to utf8 string, and parse
    const decrypted = JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8'))

    return decrypted
  }

  async getSessionData (): Promise<any> {
    await this.initialized

    try {
      let item: any
      const fileBuf = await readFile(this.filepath)
      if (this.password === undefined) {
        item = fileBuf.toString('utf8')
      } else {
        item = await this.decryptToJson(fileBuf)
      }
      if (item === '') throw new Error('invalid storage file or invalid format')
      return item
    } catch (error) {
      throw new Error('invalid storage file or invalid format')
    }
  }

  async setSessionData (json: any): Promise<void> {
    await this.initialized

    if (this.password === undefined) {
      await writeFile(this.filepath, JSON.stringify(json), { encoding: 'utf8' })
    } else {
      await writeFile(this.filepath, await this.encryptJson(json))
    }
  }

  async clear (): Promise<void> {
    await this.initialized
    await rm(this.filepath)
  }
}
