import { StoreType } from '@wallet/lib'
import { ElectronStoreBuilder } from './electron-store-builder'
import { FileStoreBuilder } from './file-store-builder'
import { StoreBuilder, StoreBuilderConstructor } from './store-builder'

const storeBuildersByType: Record<StoreType, StoreBuilderConstructor<any>> = {
  'electron-store': ElectronStoreBuilder,
  'file-store': FileStoreBuilder
}

export const currentStoreType: StoreType = 'file-store'

export const loadStoreBuilder = <T extends Record<string, any> = Record<string, unknown>>(type?: StoreType): StoreBuilder<T> => {
  const actualType = type ?? currentStoreType
  return new storeBuildersByType[actualType]()
}
