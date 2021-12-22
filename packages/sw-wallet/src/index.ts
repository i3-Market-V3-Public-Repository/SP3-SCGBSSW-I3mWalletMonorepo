import { BaseWallet, WalletBuilder } from '@i3m/base-wallet'

import { SwWalletOptions } from './types'
import { SwHdKeyWallet } from './sw-hd-wallet'

const builder: WalletBuilder<SwWalletOptions> = async (opts) => {
  const keyWallet = new SwHdKeyWallet(opts.dialog, opts.store)
  await keyWallet.initialize()

  return new BaseWallet({
    ...opts,
    keyWallet
  })
}

export default builder
