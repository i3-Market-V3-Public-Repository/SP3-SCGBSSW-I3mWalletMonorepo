import { WalletInfo } from '@wallet/lib'
import { Locals } from '@wallet/main/internal'

type Handler<T> = (walletInfo: WalletInfo, opts: T, locals: Locals) => Promise<void>

export interface FeatureHandler<T> {
  name: string
  start?: Handler<T>
  delete?: Handler<T>
  stop?: Handler<T>
}
