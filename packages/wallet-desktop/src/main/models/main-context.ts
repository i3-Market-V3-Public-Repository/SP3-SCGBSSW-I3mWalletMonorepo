import { BaseContext, PublicSettings } from '@wallet/lib'
import { Args, KeyContext, StoreMigrationProxy } from '@wallet/main/internal'

export interface MainContext extends BaseContext {
  args: Args
  storeMigrationProxy: StoreMigrationProxy
  initialPublicSettings: PublicSettings
  keyCtx?: KeyContext
}
