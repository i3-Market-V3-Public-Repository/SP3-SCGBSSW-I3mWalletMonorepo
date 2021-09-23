import {
  deleteIdentityAction
} from '@wallet/lib'
import { ActionError } from '../action-error'
import { ActionHandlerBuilder } from '../action-handler'

export const deleteIdentity: ActionHandlerBuilder<typeof deleteIdentityAction> = (
  locals
) => {
  return {
    type: deleteIdentityAction.type,
    async handle (action) {
      throw new ActionError('Not implemented yet', action)
    }
  }
}
