import { BaseWalletModel } from '@i3m/base-wallet'

import { PrivateSettings } from './private-settings'
import { PublicSettings } from './public-settings'


export interface StoreModel extends BaseWalletModel {
  start: Date
}

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
