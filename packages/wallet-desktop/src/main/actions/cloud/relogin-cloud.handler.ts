import {
  reloginCloudAction as actionBuilder
} from '@wallet/lib'
import { ActionHandlerBuilder } from '../action-handler'

export const reloginCloud: ActionHandlerBuilder<typeof actionBuilder> = (
  locals
) => {
  return {
    type: actionBuilder.type,
    async handle (action) {
      const { cloudVaultManager, sharedMemoryManager: shm } = locals

      // Call the internal function
      const credentials = shm.memory.settings.cloud?.credentials
      await cloudVaultManager.login(credentials)

      return { response: undefined, status: 200 }
    }
  }
}
