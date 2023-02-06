import { StoreModel, StoreOptions } from '@wallet/main/internal'
import { Store } from '@i3m/base-wallet'

export type WalletStore = Store<StoreModel>
export type WalletStoreOptions = StoreOptions<StoreModel>

export interface FeatureContext {
  store?: WalletStore
}
