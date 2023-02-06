import { BaseContext } from '@wallet/lib'
import { StoreMigrationProxy } from '../store/migration'

export interface MainContext extends BaseContext {
  settingsPath: string
  storeMigrationProxy: StoreMigrationProxy
  // features?: Array<Feature<any>>
}
