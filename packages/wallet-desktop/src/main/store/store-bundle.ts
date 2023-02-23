
// type WalletStoreMetadata = [type: 'wallet', walletName: string]
// type PrivateSettingsStoreMetadata = [type: 'private-settings']

import { StoreOptions } from './builders'
import { StoreClass, StoreClasses, StoreModels } from './store-class'

// export type StoreIdMetadata<T extends StoreClass> =

export interface StoreMetadata<T extends StoreClass = StoreClass> {
  type: T
  args: StoreClasses[T]
  options: StoreOptions<StoreModels[T]>
}

export interface StoreBundleData<T extends StoreClass = StoreClass> {
  metadata: StoreMetadata<T>
  data: StoreModels[T]
}

export interface StoresBundle<T extends StoreClass = StoreClass> {
  version: string
  stores: Record<string, StoreBundleData<T>>
}
