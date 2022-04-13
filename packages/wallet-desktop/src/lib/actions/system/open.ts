import { Action as BaseAction } from '../action'
import { ActionBuilder } from '../action-builder'

const type = 'system::tray.open'
type Payload = undefined
type Response = undefined
type Action = BaseAction<typeof type, Payload>

const create = (): Action => {
  return { type, payload: undefined }
}

export const openAction: ActionBuilder<Action, Response, typeof create> = {
  type: type,
  create
}
