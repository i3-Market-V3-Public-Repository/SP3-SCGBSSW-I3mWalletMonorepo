import { KeyObject } from 'crypto'

import { AuthSettings, AuthSettingsAlgorithms, EncSettings, EncSettingsAlgorithms } from '@wallet/lib'
import { Locals } from '@wallet/main/internal'

export interface KeyContext {
  password: string
  authKeys: AuthenticationKeys
  encKeys: EncryptionKeys
}

export interface EncryptionKeys<E extends EncSettingsAlgorithms = EncSettingsAlgorithms> {
  readonly algorithm: E
  get preencryptionKey (): KeyObject // eslint-disable-line @typescript-eslint/method-signature-style

  // Prepare
  prepareEncryption: (keyCtx: KeyContext) => Promise<void>

  // Keys
  // generatePreencryptionKey: (password: string) => Promise<KeyObject>
  generateWalletKey: (walletUuid: string) => Promise<KeyObject>
  generateSettingsKey: () => Promise<KeyObject>

  // Storage
  storeSettings: (locals: Locals, keyCtx: KeyContext) => Promise<void>

  // Migration
  migrationNeeded: () => Promise<boolean>
}

export type EncSettingsFor<E extends EncSettingsAlgorithms> = { algorithm: E } & EncSettings
export interface EncryptionKeysConstructor<E extends EncSettingsAlgorithms> {
  new (enc: EncSettingsFor<E>): EncryptionKeys<E>

  initialize: () => EncryptionKeys<E>
}

export interface AuthenticationKeys<A extends AuthSettingsAlgorithms = AuthSettingsAlgorithms> {
  readonly algorithm: A

  authenticate: (keyCtx: KeyContext) => Promise<boolean>
  register: (keyCtx: KeyContext) => Promise<void>
  storeSettings: (locals: Locals, keyCtx: KeyContext) => Promise<void>

  // Migration
  migrationNeeded: () => Promise<boolean>
}

export type AuthSettingsFor<A extends AuthSettingsAlgorithms> = { algorithm: A } & AuthSettings
export interface AuthenticationKeysConstructor<A extends AuthSettingsAlgorithms = AuthSettingsAlgorithms> {
  new (auth: AuthSettingsFor<A>): AuthenticationKeys

  initialize: () => AuthenticationKeys<A>
}
