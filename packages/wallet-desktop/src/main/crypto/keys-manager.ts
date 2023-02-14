import { KeyObject } from 'crypto'
import _ from 'lodash'

import { Locals, AuthenticationError, logger, WalletDesktopError, MainContext, KeyContext } from '@wallet/main/internal'
import { currentAuthAlgorithm, getCurrentAuthKeys, loadAuthKeyAlgorithm } from './authentication'
import { currentEncAlgorithm, getCurrentEncKeys, loadEncKeyAlgorithm } from './encryption'
import { AuthenticationKeys, EncryptionKeys } from './key-generators'

export class KeysManager {
  protected maxTries: number
  protected passwordRegex: RegExp
  protected passwordRegexMessage: string

  protected registered: boolean

  // pek stands for pree encryption key
  protected _pek?: KeyObject
  protected _authKeys?: AuthenticationKeys
  protected _encKeys?: EncryptionKeys

  constructor (protected ctx: MainContext, protected locals: Locals) {
    this.maxTries = 3
    this.passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d\W]{8,}$/
    this.passwordRegexMessage = 'Password must fulfill: \n - Minimum eight characters.\n - At least one uppercase letter, one lowercase letter and one number. \n - Optional: Symbols '
    this.registered = false
  }

  public async initialize (): Promise<void> {
    const auth = await this.locals.publicSettings.get('auth')
    this.registered = auth !== undefined
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

  get authenticated (): boolean {
    return this._pek !== undefined
  }

  private verifyPasswordRegex (password: string): boolean {
    const match = password.match(this.passwordRegex) !== null
    if (!match) {
      this.locals.toast.show({
        message: 'Incorrect password format',
        details: this.passwordRegexMessage,
        type: 'error'
      })
      return false
    }

    return true
  }

  private async askValidPassword (
    message: (triesLeft: number) => string,
    extraChecks: (password: string) => Promise<boolean> = async () => true
  ): Promise<string | undefined> {
    const { dialog } = this.locals

    let leftTries = this.maxTries
    while (leftTries > 0) {
      const password = await dialog.text({
        message: message(leftTries--),
        allowCancel: false,
        hiddenText: true
      })

      if (password === undefined) {
        break
      }

      if (!this.verifyPasswordRegex(password)) {
        continue
      }

      if (await extraChecks(password)) {
        return password
      } else {
        this.locals.toast.show({
          message: 'Incorrect password',
          type: 'error'
        })
      }
    }
  }

  private async initializePassword (): Promise<KeyContext> {
    const authKeys = await getCurrentAuthKeys()
    const encKeys = await getCurrentEncKeys()

    const message = (tries: number): string => `You don't have an application password: setup a new one (${tries} left).\n ${this.passwordRegexMessage}`
    const validPassword = await this.askValidPassword(message)
    if (validPassword === undefined) {
      throw new AuthenticationError('tries exceeded')
    }

    const confirmedPassword = await this.askValidPassword(
      (tries) => `Confirm your password (${tries} left).`,
      async (password) => validPassword === password
    )
    if (confirmedPassword === undefined) {
      throw new AuthenticationError('unconfirmed password')
    }

    const keyCtx: KeyContext = {
      password: validPassword,
      authKeys,
      encKeys
    }
    await keyCtx.encKeys.prepareEncryption(keyCtx)
    await keyCtx.encKeys.storeSettings(this.locals, keyCtx)

    await keyCtx.authKeys.register(keyCtx)
    await keyCtx.authKeys.storeSettings(this.locals, keyCtx)

    return keyCtx
  }

  private async localAuthentication (): Promise<KeyContext> {
    const { publicSettings } = this.locals
    const auth = await publicSettings.get('auth')
    const authKeys = loadAuthKeyAlgorithm(auth)

    const enc = await publicSettings.get('enc')
    const encKeys = loadEncKeyAlgorithm(auth, enc)

    const keyCtx: KeyContext = {
      password: '',
      authKeys,
      encKeys
    }
    const message = (tries: number): string => `Enter the application password. You have ${tries} left.`
    const validPassword = await this.askValidPassword(message, async (password) => {
      keyCtx.password = password

      const { taskManager } = this.locals
      return await taskManager.createTask('labeled', {
        title: 'Computing keys',
        details: 'Deriving cryptographic keys from password',
        freezing: true
      }, async (task) => {
        await keyCtx.encKeys.prepareEncryption(keyCtx)
        return await keyCtx.authKeys.authenticate(keyCtx)
      })
    })

    if (validPassword === undefined) {
      throw new AuthenticationError('Tries exceeded')
    }

    await this.migrate(keyCtx)

    return keyCtx
  }

  async authenticate (): Promise<KeyContext> {
    let keyCtx
    if (!this.registered) {
      keyCtx = await this.initializePassword()
      this.registered = true
    } else {
      keyCtx = await this.localAuthentication()
    }

    // Set algorithms
    this._authKeys = keyCtx.authKeys
    this._encKeys = keyCtx.encKeys

    return keyCtx
  }

  private async migrate (oldCtx: KeyContext): Promise<void> {
    const { storeMigrationProxy } = this.ctx
    const newCtx: KeyContext = _.clone(oldCtx)
    const migrateAuth = async (): Promise<void> => {
      logger.debug(`Migrate authentication keys from ${auth?.algorithm ?? 'default'} to '${currentAuthAlgorithm}'`)
      newCtx.authKeys = await getCurrentAuthKeys()

      storeMigrationProxy.migrations.push(async () => {
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
      storeMigrationProxy.migrations.push(async () => {
        await newCtx.encKeys.storeSettings(this.locals, oldCtx)
        this._encKeys = newCtx.encKeys
      })
    }

    const auth = await this.locals.publicSettings.get('auth')
    if (auth?.algorithm !== currentAuthAlgorithm) {
      await migrateAuth()
    } else if (await oldCtx.authKeys.migrationNeeded()) {
      await migrateAuth()
    }

    const enc = await this.locals.publicSettings.get('enc')
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
