import { KeyObject } from 'crypto'

import { AuthSettingsAlgorithms, BaseAuthSettings, BaseEncSettings } from '@wallet/lib'
import { Locals } from '@wallet/main/internal'

export interface KeyContext {
  password: string
  authKeys: AuthenticationKeys
  encKeys: EncryptionKeys
}

export interface EncryptionKeys {
  get preencryptionKey (): KeyObject // eslint-disable-line @typescript-eslint/method-signature-style

  // Prepare
  prepareEncryption: (keyCtx: KeyContext) => Promise<void>

  // Keys
  // generatePreencryptionKey: (password: string) => Promise<KeyObject>
  generateWalletKey: (walletUuid: string) => Promise<KeyObject>
  generateSettingsKey: () => Promise<KeyObject>

  // Storage
  storeSettings: (locals: Locals, keyCtx: KeyContext) => Promise<void>
}

export type EncryptionKeysConstructor<E extends BaseEncSettings = BaseEncSettings> = new (enc: E) => EncryptionKeys

export interface AuthenticationKeys {
  readonly type: AuthSettingsAlgorithms

  authenticate: (keyCtx: KeyContext) => Promise<boolean>
  register: (keyCtx: KeyContext) => Promise<void>
  storeSettings: (locals: Locals, keyCtx: KeyContext) => Promise<void>
}

export type AuthenticationKeysConstructor<A extends BaseAuthSettings = BaseAuthSettings> = new (auth: A) => AuthenticationKeys
