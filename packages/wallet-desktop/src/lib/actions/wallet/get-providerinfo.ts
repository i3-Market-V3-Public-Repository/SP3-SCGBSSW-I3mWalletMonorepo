import { WalletPaths } from '@i3m/wallet-desktop-openapi/types'
import { Action as BaseAction } from '../action'
import { ActionBuilder } from '../action-builder'

const type = 'wallet::providerinfo.get'
type Payload = undefined
type Response = WalletPaths.IdentitySign.Responses.$200
type Action = BaseAction<typeof type, Payload>

const create = (payload: Payload): Action => {
  return { type, payload }
}

export const getProviderinfoAction: ActionBuilder<Action, Response, typeof create> = {
  type: type,
  create
}
