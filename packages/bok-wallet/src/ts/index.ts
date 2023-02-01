import { WalletBuilder } from '@i3m/base-wallet'

import { BokWalletOptions } from './types'
import { BokKeyWallet } from './bok-key-wallet'
import { BokWallet } from './bok-wallet'
export { BokWallet } from './bok-wallet'

const builder: WalletBuilder<BokWalletOptions> = async (opts) => {
  const keyWallet = new BokKeyWallet(opts.dialog, opts.store)
  return new BokWallet({ ...opts, keyWallet })
}

export * from './types'
export default builder
