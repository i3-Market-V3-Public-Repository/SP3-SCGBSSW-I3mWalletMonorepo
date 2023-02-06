import { createSecretKey } from 'crypto'

import { Store, FileStore } from '@i3m/base-wallet'
import { Locals, MainContext } from '@wallet/main/internal'

import { StoreBuilder, StoreOptions } from './store-builder'
import { getPath } from './get-path'

export class FileStoreBuilder<T extends Record<string, any> = Record<string, unknown>> implements StoreBuilder<T> {
  async build (ctx: MainContext, locals: Locals, options: StoreOptions<T>): Promise<Store<T>> {
    const filepath = getPath(ctx, locals, options)
    let store: FileStore<T>
    if (options.encryptionKey !== undefined) {
      const key = options.encryptionKey
      if (key instanceof Buffer) {
        const secret = createSecretKey(key)
        store = new FileStore(filepath, secret, options.defaults)
      } else {
        store = new FileStore(filepath, key, options.defaults)
      }
    } else {
      store = new FileStore<T>(filepath, undefined, options.defaults)
    }
    await store.initialized

    return store
  }
}
