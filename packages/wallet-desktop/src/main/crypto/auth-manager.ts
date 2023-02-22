import { AuthenticationError, KeyContext, LabeledTaskHandler, Locals, MainContext } from '@wallet/main/internal'
import { getCurrentAuthKeys, loadAuthKeyAlgorithm } from './authentication'
import { getCurrentEncKeys, loadEncKeyAlgorithm } from './encryption'

interface AuthParams {
  registered: boolean
}

export class AuthManager {
  protected maxTries: number
  protected passwordRegex: RegExp
  protected passwordRegexMessage: string

  protected _registered: boolean
  protected _authenticated: boolean

  public static async initialize (ctx: MainContext, locals: Locals): Promise<AuthManager> {
    const publicSettings = locals.storeManager.getStore('public-settings')
    const auth = await publicSettings.get('auth')

    return new AuthManager(ctx, locals, {
      registered: auth !== undefined
    })
  }

  constructor (protected ctx: MainContext, protected locals: Locals, params: AuthParams) {
    this.maxTries = 3
    this.passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d\W]{8,}$/
    this.passwordRegexMessage = 'Password must fulfill: \n - Minimum eight characters.\n - At least one uppercase letter, one lowercase letter and one number. \n - Optional: Symbols '
    this._registered = params.registered
    this._authenticated = false

    this.bindRuntimeEvents ()
  }

  bindRuntimeEvents () {
    const { runtimeManager } = this.locals
    runtimeManager.on('auth', async (task) => {
      await this.authenticate(task)
    })
  }

  get registered (): boolean {
    return this._registered
  }

  get authenticated (): boolean {
    return this._authenticated
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

  private async localAuthRegister (): Promise<KeyContext> {
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

  private async localAuth (): Promise<KeyContext> {
    const publicSettings = this.locals.storeManager.getStore('public-settings')
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

    await this.locals.keysManager.migrate(keyCtx)

    return keyCtx
  }

  async authenticate (task: LabeledTaskHandler): Promise<KeyContext> {
    let keyCtx

    if (!this.registered) {
      keyCtx = await this.localAuthRegister()
      this._registered = true
    } else {
      keyCtx = await this.localAuth()
    }

    this._authenticated = true
    this.locals.keysManager.setKeyContext(keyCtx)

    return keyCtx
  }
}
