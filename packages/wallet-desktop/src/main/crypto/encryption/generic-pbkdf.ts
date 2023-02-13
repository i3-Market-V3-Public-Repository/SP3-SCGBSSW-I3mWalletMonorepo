import crypto, { KeyObject } from 'crypto'
import { digest } from 'object-sha'

import { GenericPbkdfEncSettings, KeyDerivationContext } from '@wallet/lib'
import { AuthenticationError, deriveKey, isKeyObject, Locals } from '@wallet/main/internal'
import { EncryptionKeys, KeyContext } from '../key-generators'

const DEFAULT_KD: GenericPbkdfEncSettings['key_derivation'] = {
  master: {
    alg: 'scrypt',
    derived_key_length: 32,
    input_pattern: '{password}',
    salt_pattern: '{salt}',
    salt_hashing_algorithm: 'sha512',
    alg_options: {
      N: 2 ** 19,
      p: 2,
      r: 8
    }
  },
  settings: {
    alg: 'scrypt',
    derived_key_length: 32,
    input_pattern: '{master}',
    salt_pattern: 'sk',
    salt_hashing_algorithm: 'sha512',
    alg_options: {
      N: 2 ** 8,
      p: 1,
      r: 8
    }
  },
  wallet: {
    alg: 'scrypt',
    derived_key_length: 32,
    input_pattern: '{master}',
    salt_pattern: 'wk-{wallet}',
    salt_hashing_algorithm: 'sha512',
    alg_options: {
      N: 2 ** 8,
      p: 1,
      r: 8
    }
  }
}

export class GenericPbkdfEncKeys implements EncryptionKeys {
  readonly algorithm = 'generic-pbkdf'

  protected kd: GenericPbkdfEncSettings['key_derivation']
  protected salt: Buffer

  private _master?: KeyObject

  constructor (enc: GenericPbkdfEncSettings) {
    this.kd = enc.key_derivation
    this.salt = Buffer.from(enc.salt, 'base64')
  }

  get preencryptionKey (): KeyObject {
    if (!isKeyObject(this._master)) {
      throw new AuthenticationError('The user is not registered. Why are you trying to authenticate?')
    }
    return this._master
  }

  get kdCtx (): KeyDerivationContext {
    return {
      master: this._master,
      salt: this.salt
    }
  }

  async prepareEncryption (keyCtx: KeyContext): Promise<void> {
    this._master = await deriveKey(this.kd.master, {
      password: keyCtx.password,
      ...this.kdCtx
    })
  }

  async generateWalletKey (walletUuid: string): Promise<KeyObject> {
    return await deriveKey(this.kd.wallet, {
      ...this.kdCtx,
      wallet: walletUuid
    })
  }

  async generateSettingsKey (): Promise<KeyObject> {
    return await deriveKey(this.kd.settings, this.kdCtx)
  }

  async storeSettings (locals: Locals, keyCtx: KeyContext): Promise<void> {
    const encSettings: GenericPbkdfEncSettings = {
      algorithm: 'generic-pbkdf',
      salt: this.salt.toString('base64'),
      key_derivation: this.kd
    }
    await locals.publicSettings.set('enc', encSettings)
  }

  async migrationNeeded (): Promise<boolean> {
    const defaultKd = await digest(DEFAULT_KD)
    const thisKd = await digest(this.kd)
    return defaultKd !== thisKd
  }

  static initialize (): GenericPbkdfEncKeys {
    const salt = crypto.randomBytes(16)

    return new GenericPbkdfEncKeys({
      algorithm: 'generic-pbkdf',
      salt: salt.toString('base64'),

      // Parameters
      key_derivation: DEFAULT_KD
    })
  }
}
