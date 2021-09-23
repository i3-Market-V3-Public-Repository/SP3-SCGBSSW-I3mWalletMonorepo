// @ts-ignore
import { WalletPaths } from '@i3-market/wallet-desktop-openapi/types'
import { BaseWalletModel } from '../app'

export interface Wallet {
  /**
   * @throws Error
   */
  wipe: () => Promise<void>

  getResources: () => Promise<BaseWalletModel['resources']>
  getIdentities: () => Promise<BaseWalletModel['identities']>

  // Api methods
  // @wallet-methods
}
