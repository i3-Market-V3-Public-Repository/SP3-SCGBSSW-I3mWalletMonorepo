import {
  reloginCloudAction as actionBuilder
} from '@wallet/lib'
import { ActionHandlerBuilder } from '@wallet/main/internal'

export const reloginCloud: ActionHandlerBuilder<typeof actionBuilder> = (
  locals
) => {
  return {
    type: actionBuilder.type,
    async handle (action) {
      const { cloudVaultManager, sharedMemoryManager: shm } = locals

      // Call the internal function
      const cloud = shm.memory.settings.cloud
      await cloudVaultManager.login(cloud)

      return { response: undefined, status: 200 }
    }
  }
}
