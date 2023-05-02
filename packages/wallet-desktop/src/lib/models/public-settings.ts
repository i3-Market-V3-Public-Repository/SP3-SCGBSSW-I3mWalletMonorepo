
import { AuthSettings, EncSettings } from './key-algorithms'

export type StoreType = 'electron-store' | 'file-store'

export interface StoreSettings {
  type?: StoreType
}

export interface CloudVaultPublicSettings {
  timestamp?: number // timestamp (milliseconds elapsed since EPOCH) when the storage was registered in the vault cloud.
  unsyncedChanges: boolean
  url?: string
}

export interface PublicSettings {
  version: string
  auth?: AuthSettings
  enc?: EncSettings
  store?: StoreSettings
  cloud?: CloudVaultPublicSettings
  currentWallet?: string // Module name of the current wallet
}

export const PUBLIC_SETTINGS_FIELDS: Array<keyof PublicSettings> = [
  'version', 'auth', 'enc', 'cloud', 'store', 'currentWallet'
]
