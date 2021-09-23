import { WalletOptions } from './wallet-options'
import { Wallet } from './wallet'

export type WalletBuilder<Options extends WalletOptions<any>> = (opts: Options) => Promise<Wallet>
