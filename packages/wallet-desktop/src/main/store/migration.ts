import { StoreType } from '@wallet/lib'
import { EncryptionKeys, StoreOptions } from '@wallet/main/internal'

export interface StoreMigration {
  cwd?: string
  encKeys?: EncryptionKeys
  storeType?: StoreType
}

export interface StoreMigrationProxy {
  needed: boolean
  from: StoreMigration
  to: StoreMigration
}

export type StoreOptionsBuilder<T extends Record<string, any> = Record<string, unknown>> =
  (migration: StoreMigration) => Promise<Partial<StoreOptions<T>>>

export const createStoreMigrationProxy = (): StoreMigrationProxy => {
  let needed = false
  const changeNeededProxyHandler: ProxyHandler<any> = {
    set (target, p, newValue, receiver) {
      needed = true
      target[p] = newValue
      return true
    },
    get (target, p, receiver) {
      if (p === 'needed') {
        return needed
      }
      return target[p]
    }
  }
  const baseProxy: StoreMigrationProxy = {
    needed: false,
    from: new Proxy({}, changeNeededProxyHandler),
    to: new Proxy({}, changeNeededProxyHandler)
  }
  return new Proxy<StoreMigrationProxy>(baseProxy, changeNeededProxyHandler)
}
