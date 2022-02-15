import { TestStore, TestDialog, BaseWallet } from '@i3m/base-wallet'
import initBokWallet from '@i3m/bok-wallet'

export default async function (): Promise<BaseWallet<any>> {
  const store = new TestStore()
  store.model = {
    resources: {},
    identities: {}
  }

  const dialog = new TestDialog()

  const wallet = await initBokWallet({ store, dialog }) as BaseWallet<any>

  return wallet
}
