import { Action as BaseAction } from '../action'
import { ActionBuilder } from '../action-builder'

const type = 'connect::walletProtocol.pairing'
type Payload = undefined
type Response = string
type Action = BaseAction<typeof type, Payload>

const create = (): Action => {
  return { type, payload: undefined }
}

export const walletProtocolPairingAction: ActionBuilder<Action, Response, typeof create> = {
  type: type,
  create
}
