import { hash, verify } from 'scrypt-mcf'
import crypto from 'crypto'

import { AuthenticationError, Locals } from '@wallet/main/internal'
import { GeneralMcfAuthSettings } from '@wallet/lib'
import { AuthenticationKeys, KeyContext } from '../key-generators'

export class GeneralMcfAuthKeys implements AuthenticationKeys {
  readonly algorithm = 'general-mcf'
  protected _localAuth?: string

  constructor (auth: GeneralMcfAuthSettings) {
    this._localAuth = auth.localAuth
  }

  get localAuth (): string {
    if (this._localAuth === undefined) {
      throw new AuthenticationError('The user is not registered. Why are you trying to authenticate?')
    }
    return this._localAuth
  }

  async register (keyCtx: KeyContext): Promise<void> {
    this._localAuth = await hash(keyCtx.password, {
      saltBase64NoPadding: crypto.randomBytes(16).toString('base64')
    })
  }

  async authenticate (keyCtx: KeyContext): Promise<boolean> {
    return await verify(keyCtx.password, this.localAuth)
  }

  async storeSettings (locals: Locals): Promise<void> {
    const auth: GeneralMcfAuthSettings = {
      algorithm: 'general-mcf',
      localAuth: this.localAuth
    }
    await locals.publicSettings.set('auth', auth)
  }

  async migrationNeeded (): Promise<boolean> {
    return false
  }

  static initialize (): GeneralMcfAuthKeys {
    return new GeneralMcfAuthKeys({
      algorithm: 'general-mcf'
    })
  }
}
