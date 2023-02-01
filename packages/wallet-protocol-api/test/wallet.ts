import { TestToast, TestStore, TestDialog, BaseWallet } from '@i3m/base-wallet'
import initBokWallet, { BokWalletModel } from '@i3m/bok-wallet'

export default async function (): Promise<BaseWallet<any>> {
  const store = new TestStore<BokWalletModel>({
    identities: {},
    keys: {},
    resources: {}
  })
  const toast = new TestToast()
  // store.model = {
  //   resources: {},
  //   identities: {}
  // }

  const dialog = new TestDialog()

  const wallet = await initBokWallet({ toast, store, dialog }) as BaseWallet<any>

  return wallet
}
