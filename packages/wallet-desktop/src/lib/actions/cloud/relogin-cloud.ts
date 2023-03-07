import { Action as BaseAction } from '../action'
import { ActionBuilder } from '../action-builder'

const type = 'cloud::user.relogin'
type Payload = undefined
type Response = undefined
type Action = BaseAction<typeof type, Payload>

const create = (): Action => {
  return { type, payload: undefined }
}

export const reloginCloudAction: ActionBuilder<Action, Response, typeof create> = {
  type: type,
  create
}
