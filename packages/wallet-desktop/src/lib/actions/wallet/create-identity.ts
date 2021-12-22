import { WalletPaths } from '@i3m/wallet-desktop-openapi/types'
import { Action as BaseAction } from '../action'
import { ActionBuilder } from '../action-builder'

const type = 'wallet::identity.create'
type Payload = WalletPaths.IdentityCreate.RequestBody
type Response = WalletPaths.IdentityCreate.Responses.$201
type Action = BaseAction<typeof type, Payload>

const create = (payload?: Payload): Action => {
  if (payload === undefined) {
    payload = {}
  }
  return { type, payload }
}

export const createIdentityAction: ActionBuilder<Action, Response, typeof create> = {
  type: type,
  create
}
