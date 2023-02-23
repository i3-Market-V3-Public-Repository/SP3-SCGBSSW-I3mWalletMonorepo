import { PrivateSettings, PublicSettings } from '@wallet/lib'
import { StoreModel } from '@wallet/main/internal'

export interface StoreClasses {
  wallet: [
    walletName: string
  ]
  'public-settings': []
  'private-settings': []
}
export interface StoreModels {
  wallet: StoreModel
  'public-settings': PublicSettings
  'private-settings': PrivateSettings
}
export type StoreClass = keyof StoreClasses
