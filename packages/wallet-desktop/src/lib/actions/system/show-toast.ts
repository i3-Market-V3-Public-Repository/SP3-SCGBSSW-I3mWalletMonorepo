import { ToastOptions } from '@i3m/base-wallet'
import { Action as BaseAction } from '../action'
import { ActionBuilder } from '../action-builder'

const type = 'system::toast.show'
type Payload = ToastOptions
type Response = undefined
type Action = BaseAction<typeof type, Payload>

const create = (opts: ToastOptions): Action => {
  return { type, payload: opts }
}

export const showToastAction: ActionBuilder<Action, Response, typeof create> = {
  type: type,
  create
}
