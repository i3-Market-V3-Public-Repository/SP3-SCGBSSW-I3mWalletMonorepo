import { OpenApiComponents } from '@i3m/cloud-vault-server/types/openapi'
import { createHash, createSecretKey, KeyObject, scrypt } from 'crypto'

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
  private _encKey!: KeyObject
  private _authKey!: KeyObject
  username: string
  derivationOptions: OpenApiComponents.Schemas.VaultConfiguration['key-derivation']
  initialized: Promise<void>

  constructor (username: string, password: string, opts: OpenApiComponents.Schemas.VaultConfiguration['key-derivation']) {
    this.username = username
    this.derivationOptions = opts
    this.initialized = this.init(password)
  }

  private async init (password: string): Promise<void> {
    const { master, auth, enc } = this.derivationOptions
    const masterSalt = _salt(master.saltHashingAlgorithm, master.saltPattern, { username: this.username })
    const masterKey = await deriveKey(password, { ...master, salt: masterSalt })

    const authSalt = _salt(auth.saltHashingAlgorithm, auth.saltPattern, { username: this.username })
    const encSalt = _salt(enc.saltHashingAlgorithm, enc.saltPattern, { username: this.username })

    const [authKey, encKey] = await Promise.all([
      deriveKey(masterKey, { ...auth, salt: authSalt }),
      deriveKey(masterKey, { ...enc, salt: encSalt })
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

function _salt (hashAlgorithm: OpenApiComponents.Schemas.KeyDerivationOptions['saltHashingAlgorithm'], saltPattern: string, replacements: { [name: string]: string }): Buffer {
  let saltString = ''
  for (const searchValue in replacements) {
    saltString = saltPattern.replaceAll(searchValue, replacements[searchValue])
  }
  const hash = createHash(hashAlgorithm)
  const salt = hash.update(saltString).digest()
  return salt
}

export async function deriveKey (password: string, opts: KeyDerivationOptions): Promise<KeyObject>
export async function deriveKey (key: KeyObject, opts: KeyDerivationOptions): Promise<KeyObject>
export async function deriveKey (passwordOrKey: string | KeyObject, opts: KeyDerivationOptions): Promise<KeyObject> {
  const scryptOptions: ScryptOptions = {
    ...opts.algOptions,
    maxmem: 256 * opts.algOptions.N * opts.algOptions.r
  }
  const password = (typeof passwordOrKey === 'string') ? passwordOrKey : passwordOrKey.export()
  const keyPromise: Promise<any> = new Promise((resolve, reject) => {
    scrypt(password, opts.salt, opts.derivedKeyLength, scryptOptions, (err, key) => {
      if (err !== null) reject(err)
      resolve(createSecretKey(key))
    })
  })
  return await keyPromise
}
