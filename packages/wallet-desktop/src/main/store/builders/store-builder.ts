import { KeyObject } from 'crypto'
import { Store } from '@i3m/base-wallet'

import { StoreType } from '@wallet/lib'
import { Locals, MainContext } from '@wallet/main/internal'

export interface StoreOptions<T> {
  defaults?: Readonly<T>
  cwd?: string
  fileExtension: string
  name: string

  //
  encryptionKey?: KeyObject
  storeType?: StoreType
}

export interface StoreBuilder<T extends Record<string, any> = Record<string, unknown>> {
  build: (ctx: MainContext, locals: Locals, options: StoreOptions<T>) => Promise<Store<T>>
}

export type StoreBuilderConstructor<T extends Record<string, any> = Record<string, unknown>> = new () => StoreBuilder<T>
