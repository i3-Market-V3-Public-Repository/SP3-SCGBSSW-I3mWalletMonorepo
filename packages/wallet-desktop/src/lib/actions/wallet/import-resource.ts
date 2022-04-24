import { Action as BaseAction } from '../action'
import { ActionBuilder } from '../action-builder'

const type = 'wallet::resource.import'
type Payload = string | undefined // identity DID
type Response = undefined
type Action = BaseAction<typeof type, Payload>

const create = (payload: Payload): Action => {
  return { type, payload }
}

export const importResourceAction: ActionBuilder<Action, Response, typeof create> = {
  type: type,
  create
}
