import { FeatureHandler } from './feature-handler'

export interface StoreFeatureOptions {
  encryption?: {
    enabled?: boolean
    tries?: number
    passwordRegex?: RegExp
  }
  name?: string
  storePath?: string
}

export const storeFeature: FeatureHandler<StoreFeatureOptions> = {
  name: 'store',

  async start (walletName, opts, locals) {
    const { storeManager } = locals
    if (!storeManager.hasStore('wallet', walletName)) {
      await storeManager.buildWalletStore(walletName)
    }
    // TODO: Should we allow use the getStore method outside??
    locals.featureContext.store = storeManager.getStore('wallet', walletName)
    locals.sharedMemoryManager.update((mem) => ({ ...mem, hasStore: true }))
  },

  async delete (walletName, opts, locals) {
    const { storeManager } = locals
    if (storeManager.hasStore('wallet', walletName)) {
      storeManager.deleteStore('wallet', walletName)
    }
  },

  async stop (walletName, opts, locals) {
    delete locals.featureContext.store
    locals.sharedMemoryManager.update((mem) => ({ ...mem, hasStore: false }))
  }
}
