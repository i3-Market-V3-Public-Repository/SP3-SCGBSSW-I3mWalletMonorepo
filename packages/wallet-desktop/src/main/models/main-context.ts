import { BaseContext } from '@wallet/lib'
import { StoreMigrationProxy } from '@wallet/main/internal'

export interface MainContext extends BaseContext {
  settingsPath: string
  storeMigrationProxy: StoreMigrationProxy
}
