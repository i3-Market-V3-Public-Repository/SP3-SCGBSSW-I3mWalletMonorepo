import { CanBePromise, Store } from '@i3m/base-wallet'
import { Locals, MainContext } from '@wallet/main/internal'
import ElectronStore from 'electron-store'
import { StoreBuilder, StoreOptions } from './store-builder'

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
    const { encryptionKey, ...electronStoreOptions} = options
    return new ElectronStoreExtra({
      encryptionKey: encryptionKey?.export(),
      ...electronStoreOptions
    })
  }
}
