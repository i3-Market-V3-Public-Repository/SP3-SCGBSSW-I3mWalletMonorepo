import { Action as BaseAction } from '../action'
import { ActionBuilder } from '../action-builder'

const type = 'wallet::wallet.select'
type Payload = { wallet: string } | undefined
type Response = undefined
type Action = BaseAction<typeof type, Payload>

export const selectWalletAction: ActionBuilder<Action, Response> = {
  type: type,
  create: (wallet: string) => {
    if (wallet === undefined) {
      return { type, payload: undefined }
    }
    return { type, payload: { wallet } }
  }
}
