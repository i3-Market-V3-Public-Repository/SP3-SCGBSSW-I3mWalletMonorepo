import { Action as BaseAction } from '../action'
import { ActionBuilder } from '../action-builder'

const type = 'wallet::wallet.create'
type Payload = undefined
type Response = undefined
type Action = BaseAction<typeof type, Payload>

export const createWalletAction: ActionBuilder<Action, Response> = {
  type: type,
  create: () => {
    return { type, payload: undefined }
  }
}
