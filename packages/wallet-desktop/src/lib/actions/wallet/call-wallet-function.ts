import { WalletFunctionMetadata } from '@i3-market/base-wallet'
import { Action as BaseAction } from '../action'
import { ActionBuilder } from '../action-builder'

const type = 'wallet::wallet.call'
type Payload = WalletFunctionMetadata
type Response = undefined
type Action = BaseAction<typeof type, Payload>

const create = (payload: Payload): Action => {
  return { type, payload }
}

export const callWalletFunctionAction: ActionBuilder<Action, Response, typeof create> = {
  type: type,
  create
}
