import { ActionBuilder, GetAction, GetType } from '@wallet/lib'

import { Locals } from '../internal'
import { ActionResult } from './action-result'

export interface ActionHandler<B extends ActionBuilder = ActionBuilder> {
  type: GetType<B>
  handle: (action: GetAction<B>) => Promise<ActionResult>
}

export type ActionHandlerBuilder<T extends ActionBuilder = ActionBuilder> =
  (locals: Locals) => ActionHandler<T>
