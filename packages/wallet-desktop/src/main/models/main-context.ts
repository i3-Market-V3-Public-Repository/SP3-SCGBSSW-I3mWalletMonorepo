import { BaseContext } from '@wallet/lib'
import { Args, StoreMigrationProxy } from '@wallet/main/internal'

export interface MainContext extends BaseContext {
  args: Args
  storeMigrationProxy: StoreMigrationProxy
}
