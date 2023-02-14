import {
  startCloudSyncAction as actionBuilder
} from '@wallet/lib'
import { ActionHandlerBuilder } from '../action-handler'

export const startCloudSync: ActionHandlerBuilder<typeof actionBuilder> = (
  locals
) => {
  return {
    type: actionBuilder.type,
    async handle (action) {
      const { cloudVaultManager } = locals

      // Call the internal function
      await cloudVaultManager.startVaultSync()

      return { response: undefined, status: 200 }
    }
  }
}
