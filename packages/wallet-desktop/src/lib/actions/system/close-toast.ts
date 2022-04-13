import { Action as BaseAction } from '../action'
import { ActionBuilder } from '../action-builder'

const type = 'system::toast.close'
type Payload = string
type Response = undefined
type Action = BaseAction<typeof type, Payload>

const create = (toastId: string): Action => {
  return { type, payload: toastId }
}

export const closeToastAction: ActionBuilder<Action, Response, typeof create> = {
  type: type,
  create
}
