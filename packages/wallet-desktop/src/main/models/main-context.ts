import { BaseContext, PrivateSettings, PublicSettings } from '@wallet/lib'
import { Args, KeyContext } from '@wallet/main/internal'

export interface MainContext extends BaseContext {
  args: Args
  initialPublicSettings?: PublicSettings
  initialPrivateSettings?: PrivateSettings
  keyCtx?: KeyContext
}
