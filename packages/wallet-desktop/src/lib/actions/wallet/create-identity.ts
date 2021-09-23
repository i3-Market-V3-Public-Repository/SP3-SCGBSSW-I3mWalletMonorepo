import { WalletPaths } from '@i3-market/wallet-desktop-openapi/types'
import { Action as BaseAction } from '../action'
import { ActionBuilder } from '../action-builder'

const type = 'wallet::identity.create'
type Payload = WalletPaths.IdentityCreate.RequestBody
type Response = WalletPaths.IdentityCreate.Responses.$201
type Action = BaseAction<typeof type, Payload>

export const createIdentityAction: ActionBuilder<Action, Response> = {
  type: type,
  create: (alias) => {
    return { type, payload: { alias: alias } }
  }
}
