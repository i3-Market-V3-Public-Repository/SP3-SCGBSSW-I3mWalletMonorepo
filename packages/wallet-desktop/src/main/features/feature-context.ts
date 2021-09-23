import ElectronStore, { Options as ElectronStoreOptions } from 'electron-store'
import { StoreModel } from '@wallet/main/internal'

export type Store = ElectronStore<StoreModel>
export type StoreOptions = ElectronStoreOptions<StoreModel>

export interface FeatureContext {
  store?: Store
}
