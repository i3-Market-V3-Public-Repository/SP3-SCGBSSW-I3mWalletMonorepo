import {
  deleteResourceAction
} from '@wallet/lib'
import { ActionError } from '../action-error'
import { ActionHandlerBuilder } from '../action-handler'

export const deleteResource: ActionHandlerBuilder<typeof deleteResourceAction> = (
  locals
) => {
  return {
    type: deleteResourceAction.type,
    async handle (action) {
      throw new ActionError('Not implemented yet', action)
    }
  }
}
