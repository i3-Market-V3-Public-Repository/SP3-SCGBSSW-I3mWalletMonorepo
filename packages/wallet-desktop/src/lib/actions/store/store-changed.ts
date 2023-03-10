import { Store } from '@i3m/base-wallet'
import { StoreClass, StoreModels } from '@wallet/lib/internal'

import { Action as BaseAction } from '../action'
import { ActionBuilder } from '../action-builder'

const type = 'store::store.changed'
type Payload<T extends StoreClass = StoreClass> = [type: T, store: Store<StoreModels[T]>]
type Response = undefined
type Action = BaseAction<typeof type, Payload>

const create = (payload: Payload): Action => {
  return { type, payload }
}

export const storeChangedAction: ActionBuilder<Action, Response, typeof create> = {
  type: type,
  create
}
