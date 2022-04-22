import { Action as BaseAction } from '../action'
import { ActionBuilder } from '../action-builder'

const type = 'wallet::identity.delete'
type Payload = string | undefined
type Response = undefined
type Action = BaseAction<typeof type, Payload>

const create = (payload: Payload): Action => {
  return { type, payload }
}

export const deleteIdentityAction: ActionBuilder<Action, Response, typeof create> = {
  type: type,
  create
}
