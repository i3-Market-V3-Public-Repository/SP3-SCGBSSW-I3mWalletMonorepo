import { Dialog, Store, BaseWalletModel } from '../app'
import { KeyWallet } from '../keywallet'

export interface WalletOptionsCryptoWallet {
  keyWallet: KeyWallet
}
export interface WalletOptionsSettings<T extends BaseWalletModel> {
  dialog: Dialog
  store: Store<T>
  provider?: string
}

export type WalletOptions<T extends BaseWalletModel> = WalletOptionsSettings<T> & WalletOptionsCryptoWallet
