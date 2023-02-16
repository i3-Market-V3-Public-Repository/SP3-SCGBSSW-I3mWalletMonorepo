import crypto, { KeyObject } from 'crypto'

import { AuthenticationError, deriveKeyOld, InvalidSettingsError, isKeyObject, Locals, PbkdfSettings } from '@wallet/main/internal'
import { EncryptionKeys, KeyContext } from '../key-generators'
import { AuthSettings, Pbkdf2AuthSettings, Pbkdf2EncSettings } from '@wallet/lib'

function isPbkdf2AuthSettings (settings: AuthSettings): settings is Pbkdf2AuthSettings {
  return typeof (settings as any).salt !== 'undefined' && typeof (settings as any).algorithm === 'undefined'
}

export class Pbkdf2EncKeys implements EncryptionKeys {
  readonly algorithm = 'pbkdf.2'

  protected pekSettings: PbkdfSettings
  protected salt: Buffer

  private _pek?: KeyObject

  constructor (enc: Pbkdf2EncSettings) {
    this.pekSettings = {
      iterations: 50000,
      keyLength: 32,
      usage: 'pek'
    }

    if (enc.salt !== undefined) {
      this.salt = Buffer.from(enc.salt, 'base64')
    } else {
      this.salt = crypto.randomBytes(16)
    }
  }

  get preencryptionKey (): KeyObject {
    if (!isKeyObject(this._pek)) {
      throw new AuthenticationError('The user is not registered. Why are you trying to authenticate?')
    }
    return this._pek
  }

  async prepareEncryption (keyCtx: KeyContext): Promise<void> {
    this._pek = await deriveKeyOld(keyCtx.password, this.salt, this.pekSettings)
  }

  async generateWalletKey (walletUuid: string): Promise<KeyObject> {
    const wkSettings: PbkdfSettings = {
      ...this.pekSettings,
      usage: walletUuid
    }

    const pekBuffer = this.preencryptionKey.export()
    const salt = crypto.createHash('sha256').update(pekBuffer).digest()

    return await deriveKeyOld(pekBuffer, salt.subarray(0, 15), wkSettings)
  }

  async generateSettingsKey (): Promise<KeyObject> {
    const wkSettings: PbkdfSettings = {
      ...this.pekSettings,
      usage: 'sek'
    }

    const pekBuffer = this.preencryptionKey.export()
    return await deriveKeyOld(pekBuffer, Buffer.alloc(16), wkSettings)
  }

  async storeSettings (locals: Locals, keyCtx: KeyContext): Promise<void> {
    const publicSettings = locals.storeManager.getStore('public-settings')
    await publicSettings.set('enc', {
      algorithm: 'pbkdf.2',
      salt: this.salt.toString('base64')
    })
  }

  async migrationNeeded (): Promise<boolean> {
    return false
  }

  static initialize (): Pbkdf2EncKeys {
    const salt = crypto.randomBytes(16)

    return new Pbkdf2EncKeys({
      algorithm: 'pbkdf.2',
      salt: salt.toString('base64')
    })
  }

  static fromAuth (auth: AuthSettings): Pbkdf2EncKeys {
    if (isPbkdf2AuthSettings(auth)) {
      return new Pbkdf2EncKeys(auth)
    }
    throw new InvalidSettingsError('Wrong authentication settings')
  }
}
