
interface WalletStoreMetadata {
  type: 'wallet'
  walletName: string
}

interface PrivateSettingsStoreMetadata {
  type: 'private-settings'
}

export type StoreMetadata = WalletStoreMetadata | PrivateSettingsStoreMetadata

export interface StoreBundleData<T> {
  metadata: StoreMetadata
  data: T
}

export interface StoresBundle<T = unknown> {
  version: string
  stores: Record<string, StoreBundleData<T>>
} 
