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

  async start (walletInfo, opts, locals) {
    const { storeManager } = locals
    if (!storeManager.hasStore('wallet', walletInfo.name)) {
      await storeManager.buildWalletStore(walletInfo)
    }
    // TODO: Should we allow use the getStore method outside??
    locals.featureContext.store = storeManager.getStore('wallet', walletInfo.name)
    locals.sharedMemoryManager.update((mem) => ({ ...mem, hasStore: true }))
  },

  async delete (walletInfo, opts, locals) {
    const { storeManager } = locals
    if (storeManager.hasStore('wallet', walletInfo.name)) {
      storeManager.deleteStore('wallet', walletInfo.name)
    }
  },

  async stop (walletInfo, opts, locals) {
    delete locals.featureContext.store
    locals.sharedMemoryManager.update((mem) => ({ ...mem, hasStore: false }))
  }
}
