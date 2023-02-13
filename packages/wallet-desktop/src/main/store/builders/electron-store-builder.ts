import { CanBePromise, Store } from '@i3m/base-wallet'
import ElectronStore from 'electron-store'

import { DecryptionError, Locals, MainContext } from '@wallet/main/internal'
import { StoreBuilder, StoreOptions } from './store-builder'
import { getPath } from './get-path'

class ElectronStoreExtra<T extends Record<string, any> = Record<string, unknown>>
  extends ElectronStore<T> implements Store<T> {
  getStore (): CanBePromise<T> {
    return this.store
  }

  getPath (): string {
    return this.path
  }
}

export class ElectronStoreBuilder<T extends Record<string, any> = Record<string, unknown>> implements StoreBuilder<T> {
  async build (ctx: MainContext, locals: Locals, options: StoreOptions<T>): Promise<Store<T>> {
    const { encryptionKey, ...electronStoreOptions } = options
    const path = getPath(ctx, locals, options)

    try {
      return new ElectronStoreExtra({
        encryptionKey: encryptionKey?.export(),
        ...electronStoreOptions
      })
    } catch (e) {
      if (e instanceof SyntaxError) {
        throw new DecryptionError(`Inconsistent format on file '${path}'`)
      }
      throw e
    }
  }
}
