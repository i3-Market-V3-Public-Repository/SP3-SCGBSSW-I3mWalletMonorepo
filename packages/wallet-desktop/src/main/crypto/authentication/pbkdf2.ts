import crypto, { KeyObject } from 'crypto'

import { AuthenticationError, deriveKeyOld, isKeyObject, Locals, PbkdfSettings } from '@wallet/main/internal'
import { Pbkdf2AuthSettings } from '@wallet/lib'
import { AuthenticationKeys, KeyContext } from '../key-generators'

const authPbkdfSettings: PbkdfSettings = {
  iterations: 100000,
  keyLength: 32,
  usage: 'local'
}

export class Pbkdf2AuthKeys implements AuthenticationKeys {
  readonly algorithm = 'pbkdf.2'

  protected salt: Buffer
  protected _localAuth?: KeyObject

  constructor (auth: Pbkdf2AuthSettings) {
    if (auth.salt !== undefined) {
      this.salt = Buffer.from(auth.salt, 'base64')
    } else {
      this.salt = crypto.randomBytes(16)
    }

    if (auth.localAuth !== undefined) {
      this._localAuth = crypto.createSecretKey(Buffer.from(auth.localAuth, 'base64'))
    }
  }

  get localAuth (): KeyObject {
    if (!isKeyObject(this._localAuth)) {
      throw new AuthenticationError('The user is not registered. Why are you trying to authenticate?')
    }
    return this._localAuth
  }

  async generateAuthKey (keyCtx: KeyContext): Promise<KeyObject> {
    return await deriveKeyOld(keyCtx.password, this.salt, authPbkdfSettings)
  }

  async register (keyCtx: KeyContext): Promise<void> {
    this._localAuth = await this.generateAuthKey(keyCtx)
  }

  async authenticate (keyCtx: KeyContext): Promise<boolean> {
    const localAuth = (await this.generateAuthKey(keyCtx))
    return this.localAuth.export().equals(new Uint8Array(localAuth.export()))
  }

  async storeSettings (locals: Locals): Promise<void> {
    const auth: Pbkdf2AuthSettings = {
      algorithm: 'pbkdf.2',
      salt: this.salt.toString('base64'),
      localAuth: this.localAuth.export().toString('base64')
    }

    const { sharedMemoryManager: shm } = locals
    shm.update((mem) => ({
      ...mem,
      settings: {
        ...mem.settings,
        public: {
          ...mem.settings.public,
          auth
        }
      }
    }))
  }

  async migrationNeeded (): Promise<boolean> {
    return false
  }

  static initialize (): Pbkdf2AuthKeys {
    const salt = crypto.randomBytes(16)

    return new Pbkdf2AuthKeys({
      algorithm: 'pbkdf.2',
      salt: salt.toString('base64')
    })
  }
}
