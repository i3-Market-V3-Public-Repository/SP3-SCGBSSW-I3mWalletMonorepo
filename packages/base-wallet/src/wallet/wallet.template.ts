// @ts-ignore
import { WalletPaths } from '@i3m/wallet-desktop-openapi/types'
import { BaseWalletModel } from '../app'
import { WalletFunctionMetadata } from './wallet-metadata'

export interface Wallet {
  call: (functionMetadata: WalletFunctionMetadata) => Promise<void>

  getResources: () => Promise<BaseWalletModel['resources']>
  getIdentities: () => Promise<BaseWalletModel['identities']>

  // Api methods
  // @wallet-methods
}
