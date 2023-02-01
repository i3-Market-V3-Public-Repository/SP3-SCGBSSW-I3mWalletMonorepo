import { BinaryLike, KeyObject, createCipheriv, createDecipheriv, createSecretKey, randomBytes, scrypt } from 'crypto'
import { tmpdir } from 'os'
import { mkdir, readFile, writeFile, rm } from 'fs/promises'
import { dirname, join } from 'path'
import { SessionStorage, SessionFileStorageOptions } from '../types'

export class SessionFileStorage implements SessionStorage {
  filepath: string // a path to the file that will be used to store wallet session data
  private readonly password?: string // if provided a key will be derived from the password and the store file will be encrypted
  private salt?: Buffer
  private key?: KeyObject
  initialized: Promise<void>

  constructor (options?: SessionFileStorageOptions) {
    this.filepath = (typeof options?.filepath === 'string' && options.filepath !== '') ? options.filepath : join(tmpdir(), 'i3m-wallet-session')
    this.password = options?.password
    this.initialized = this.init()
  }

  private async deriveKey (password: string, salt?: Buffer): Promise<void> {
    this.salt = salt ?? randomBytes(64)
    // derive encryption key
    this.key = await deriveKey(password, {
      alg: 'scrypt',
      derivedKeyLength: 32,
      salt: this.salt
    })
  }

  private async init (): Promise<void> {
    await mkdir(dirname(this.filepath), { recursive: true })
    if (this.password !== undefined) {
      await this.deriveKey(this.password)
    }
  }

  private async encryptJson (json: any): Promise<Buffer> {
    if (this.key === undefined || this.password === undefined || this.salt === undefined) {
      throw new Error('For the session to be encrypted you must provide a password')
    }

    const plaintext = JSON.stringify(json)

    // random initialization vector
    const iv = randomBytes(16)

    // AES 256 GCM Mode
    const cipher = createCipheriv('aes-256-gcm', this.key, iv)

    // encrypt the given text
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])

    // extract the auth tag
    const tag = cipher.getAuthTag()

    // generate output
    return Buffer.concat([this.salt, iv, tag, encrypted])
  }

  private async decryptToJson (cryptogram: ArrayBufferLike): Promise<any> {
    if (this.key === undefined || this.password === undefined || this.salt === undefined) {
      throw new Error('For the session to be encrypted you must provide a password')
    }

    // extract all parts
    const buf = Buffer.from(cryptogram)
    const salt = buf.subarray(0, 64)
    if (salt.compare(this.salt) !== 0) { // eslint-disable-line @typescript-eslint/no-non-null-assertion
      await this.deriveKey(this.password, salt)
    }
    const iv = buf.subarray(64, 80)
    const tag = buf.subarray(80, 96)
    const ciphertext = buf.subarray(96)

    // AES 256 GCM Mode
    const decipher = createDecipheriv('aes-256-gcm', this.key, iv)
    decipher.setAuthTag(tag)

    // decrypt, pass to utf8 string, and parse
    const decrypted = JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8'))

    return decrypted
  }

  async getSessionData (): Promise<any> {
    await this.initialized

    let item: any
    const fileBuf = await readFile(this.filepath)
    if (this.password === undefined) {
      item = fileBuf.toString('utf8')
    } else {
      item = await this.decryptToJson(fileBuf)
    }
    if (item === '') throw new Error('invalid storage file or invalid format')
    return item
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
    await rm(this.filepath, { force: true })
  }
}

export interface ScryptOptions {
  N?: number
  r?: number
  p?: number
  maxmem?: number
}

interface KdfOptions {
  alg: 'scrypt'
  derivedKeyLength: number // in octets
  salt: BinaryLike
  algOptions?: ScryptOptions
}

async function deriveKey (password: BinaryLike, opts: KdfOptions, returnBuffer?: false): Promise<KeyObject>
async function deriveKey (password: BinaryLike, opts: KdfOptions, returnBuffer: true): Promise<Buffer>
async function deriveKey<T extends Buffer | KeyObject> (password: BinaryLike, opts: KdfOptions, returnBuffer = false): Promise<T> {
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
