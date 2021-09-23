import { Dialog, Store, BaseWalletModel } from '../app'

export interface WalletOptions<T extends BaseWalletModel> {
  dialog: Dialog
  store: Store<T>
  provider?: string
}
