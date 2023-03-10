import { StoreClass } from "@wallet/lib"

type EncryptedStoreClass = 'wallet' | 'private-settings'
export function isEncryptedStore (type: StoreClass): type is EncryptedStoreClass {
  return type !== 'public-settings'
}
