import { KeyObject } from 'crypto'
import _ from 'lodash'

import { KeyContext, Locals, logger, MainContext, WalletDesktopError } from '@wallet/main/internal'
import { currentAuthAlgorithm, getCurrentAuthKeys } from './authentication'
import { currentEncAlgorithm, getCurrentEncKeys } from './encryption'
import { AuthenticationKeys, EncryptionKeys } from './key-generators'

export class KeysManager {
  // pek stands for pree encryption key
  protected _authKeys?: AuthenticationKeys
  protected _encKeys?: EncryptionKeys

  constructor (protected ctx: MainContext, protected locals: Locals) { }

  get authKeys (): AuthenticationKeys {
    if (this._authKeys === undefined) {
      throw new WalletDesktopError('KeyManager not properly initialized!')
    }
    return this._authKeys
  }

  get encKeys (): EncryptionKeys {
    if (this._encKeys === undefined) {
      throw new WalletDesktopError('KeyManager not properly initialized!')
    }
    return this._encKeys
  }

  public setKeyContext (keyCtx: KeyContext): void {
    this._authKeys = keyCtx.authKeys
    this._encKeys = keyCtx.encKeys
  }

  public async migrate (oldCtx: KeyContext): Promise<void> {
    const { storeMigrationProxy } = this.ctx
    const { runtimeManager } = this.locals

    const newCtx: KeyContext = _.clone(oldCtx)
    const migrateAuth = async (): Promise<void> => {
      logger.debug(`Migrate authentication keys from ${auth?.algorithm ?? 'default'} to '${currentAuthAlgorithm}'`)
      newCtx.authKeys = await getCurrentAuthKeys()

      runtimeManager.on('migration', async () => {
        await newCtx.authKeys.register(newCtx)
        await newCtx.authKeys.storeSettings(this.locals, newCtx)
        this._authKeys = newCtx.authKeys
      })
    }
    const migrateEnc = async (): Promise<void> => {
      logger.debug(`Migrate encryption keys from '${enc?.algorithm ?? 'default'}' to '${currentEncAlgorithm}'`)

      newCtx.encKeys = await getCurrentEncKeys()
      await newCtx.encKeys.prepareEncryption(oldCtx)

      storeMigrationProxy.to.encKeys = newCtx.encKeys
      storeMigrationProxy.from.encKeys = oldCtx.encKeys
      runtimeManager.on('migration', async () => {
        await newCtx.encKeys.storeSettings(this.locals, oldCtx)
        this._encKeys = newCtx.encKeys
      })
    }

    const publicSettings = this.locals.storeManager.getStore('public-settings')
    const auth = await publicSettings.get('auth')
    if (auth?.algorithm !== currentAuthAlgorithm) {
      await migrateAuth()
    } else if (await oldCtx.authKeys.migrationNeeded()) {
      await migrateAuth()
    }

    const enc = await publicSettings.get('enc')
    if (enc?.algorithm !== currentEncAlgorithm) {
      await migrateEnc()
    } else if (await oldCtx.encKeys.migrationNeeded()) {
      await migrateEnc()
    }
  }

  async computeWalletKey (walletUuid: string, encKeys = this.encKeys): Promise<KeyObject> {
    return await encKeys.generateWalletKey(walletUuid)
  }

  async computeSettingsKey (encKeys = this.encKeys): Promise<KeyObject> {
    return await encKeys.generateSettingsKey()
  }
}
