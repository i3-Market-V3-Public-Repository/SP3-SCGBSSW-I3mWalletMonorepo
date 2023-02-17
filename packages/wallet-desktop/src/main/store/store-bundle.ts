
// type WalletStoreMetadata = [type: 'wallet', walletName: string]
// type PrivateSettingsStoreMetadata = [type: 'private-settings']

import { StoreClass, StoreClasses, StoreModels } from './store-class'

export type StoreIdMetadata<T extends StoreClass> = [type: T, ...args: StoreClasses[T]]

export interface StoreMetadata<T extends StoreClass = StoreClass> {
  idMetadata: StoreIdMetadata<T>
}

export interface StoreBundleData<T extends StoreClass = StoreClass> {
  metadata: StoreMetadata<T>
  data: StoreModels[T]
}

export interface StoresBundle<T extends StoreClass = StoreClass> {
  version: string
  stores: Record<string, StoreBundleData<T>>
}
