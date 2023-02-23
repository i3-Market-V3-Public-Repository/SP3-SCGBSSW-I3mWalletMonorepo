import { OpenApiComponents } from '@i3m/cloud-vault-server/types/openapi'
import { createHash, createSecretKey, KeyObject } from 'crypto'
import { Worker } from 'worker_threads'
import { SecretKey } from './secret-key'
import './scrypt-thread'
import type { scryptThreadWorkerData } from './scrypt-thread'

export interface ScryptOptions {
  N: number
  r: number
  p: number
  maxmem: number
}

export interface KeyDerivationOptions extends OpenApiComponents.Schemas.KeyDerivationOptions {
  salt: Buffer
}

export class KeyManager {
  private _encKey!: SecretKey
  private _authKey!: KeyObject
  username: string
  derivationOptions: OpenApiComponents.Schemas.VaultConfiguration['key_derivation']
  initialized: Promise<void>
  private _initialized: boolean

  constructor (username: string, password: string, opts: OpenApiComponents.Schemas.VaultConfiguration['key_derivation']) {
    this.username = username
    this.derivationOptions = opts
    this._initialized = false
    this.initialized = this.init(password)
  }

  private async init (password: string): Promise<void> {
    const { master, auth, enc } = this.derivationOptions
    const masterSalt = _salt(master.salt_hashing_algorithm, master.salt_pattern, { username: this.username })
    const masterKey = await deriveKey(password, { ...master, salt: masterSalt })

    const authSalt = _salt(auth.salt_hashing_algorithm, auth.salt_pattern, { username: this.username })
    const encSalt = _salt(enc.salt_hashing_algorithm, enc.salt_pattern, { username: this.username })

    const [authKey, encKey] = await Promise.all([
      deriveKey(masterKey, { ...auth, salt: authSalt }),
      deriveKey(masterKey, { ...enc, salt: encSalt })
    ])

    this._authKey = authKey
    this._encKey = new SecretKey(encKey, enc.enc_algorithm)
    this._initialized = true
  }

  get authKey (): string {
    if (!this._initialized) {
      throw new Error('Unable to get authKey. KeyManager not initialized', { cause: 'You may have forgotten to await keymanager.initialized or just to login' })
    }
    return this._authKey.export().toString('base64url')
  }

  get encKey (): SecretKey {
    if (!this._initialized) {
      throw new Error('Unable to get encKey. KeyManager not initialized', { cause: 'You may have forgotten to await keymanager.initialized or just to login' })
    }
    return this._encKey
  }
}

function _salt (hashAlgorithm: OpenApiComponents.Schemas.KeyDerivationOptions['salt_hashing_algorithm'], saltPattern: string, replacements: { [name: string]: string }): Buffer {
  let saltString = ''
  for (const searchValue in replacements) {
    saltString = saltPattern.replace(searchValue, replacements[searchValue])
  }
  const hash = createHash(hashAlgorithm)
  const salt = hash.update(saltString).digest()
  return salt
}

export async function deriveKey (password: string, opts: KeyDerivationOptions): Promise<KeyObject>
export async function deriveKey (key: KeyObject, opts: KeyDerivationOptions): Promise<KeyObject>
export async function deriveKey (passwordOrKey: string | KeyObject, opts: KeyDerivationOptions): Promise<KeyObject> {
  return await new Promise((resolve, reject) => {
    const workerData: scryptThreadWorkerData = {
      _name: 'scrypt-thread',
      passwordOrKey,
      opts
    }
    const worker = new Worker(__filename, { workerData })
    worker.on('message', (derivedKey: Buffer) => {
      resolve(createSecretKey(derivedKey))
    })
    worker.on('error', (err) => {
      reject(err)
    })
    worker.on('messageerror', (err) => {
      reject(err)
    })
  })
}
