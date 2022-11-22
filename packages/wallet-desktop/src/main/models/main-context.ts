import { BaseContext } from '@wallet/lib'

export interface MainContext extends BaseContext {
  settingsPath: string
  // features?: Array<Feature<any>>
}
