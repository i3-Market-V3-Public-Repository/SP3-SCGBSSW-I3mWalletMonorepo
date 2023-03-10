
import { StoreClass, StoreClasses, StoreModels } from '@wallet/lib'

import { StoreOptions } from './builders'


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
