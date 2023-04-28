import { KeyObject } from 'crypto'

import { KeyContext, Locals, logger, MainContext, WalletDesktopError } from '@wallet/main/internal'
import { currentAuthAlgorithm, getCurrentAuthKeys } from './authentication'
import { currentEncAlgorithm, getCurrentEncKeys } from './encryption'
import { AuthenticationKeys, EncryptionKeys } from './key-generators'

export class KeysManager {
  // pek stands for pree encryption key
  protected _authKeys?: AuthenticationKeys
  protected _encKeys?: EncryptionKeys

  static async initialize (ctx: MainContext, locals: Locals): Promise<KeysManager> {
    return new KeysManager(ctx, locals)
  }

  constructor (protected ctx: MainContext, protected locals: Locals) {
    this.bindRuntimeEvents()
  }

  bindRuntimeEvents (): void {
    const { runtimeManager } = this.locals
    runtimeManager.on('after-migration', async () => {
      delete this.ctx.keyCtx
    })
  }

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

  public async migrate (keyCtx: KeyContext): Promise<void> {
    const { sharedMemoryManager: shm, runtimeManager } = this.locals

    const { auth, enc } = shm.memory.settings.public
    const authMigrationNeeded = auth?.algorithm !== currentAuthAlgorithm || await keyCtx.authKeys.migrationNeeded()
    if (authMigrationNeeded) {
      runtimeManager.on('migration', async () => {
        logger.debug(`Migrate authentication keys from ${auth?.algorithm ?? 'default'} to '${currentAuthAlgorithm}'`)
        const authKeys = await getCurrentAuthKeys()
        await authKeys.register(keyCtx)
        await authKeys.storeSettings(this.locals, keyCtx)
      })
    }

    const encMigrationNeeded = enc?.algorithm !== currentEncAlgorithm || await keyCtx.encKeys.migrationNeeded()
    if (encMigrationNeeded) {
      runtimeManager.on('migration', async () => {
        logger.debug(`Migrate encryption keys from '${enc?.algorithm ?? 'default'}' to '${currentEncAlgorithm}'`)

        const encKeys = await getCurrentEncKeys()
        await encKeys.storeSettings(this.locals, keyCtx)
        await encKeys.prepareEncryption(keyCtx)
      })
    }
  }

  isCurrentEncKey (encKeys = this.encKeys): boolean {
    return encKeys === this.encKeys
  }

  async computeWalletKey (walletUuid: string, encKeys = this.encKeys): Promise<KeyObject> {
    return await encKeys.generateWalletKey(walletUuid)
  }

  async computeSettingsKey (encKeys = this.encKeys): Promise<KeyObject> {
    return await encKeys.generateSettingsKey()
  }
}
