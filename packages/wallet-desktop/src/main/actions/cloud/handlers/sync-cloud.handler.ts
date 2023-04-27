import {
  syncCloudAction as actionBuilder
} from '@wallet/lib'
import { ActionHandlerBuilder } from '@wallet/main/internal'

export const syncCloud: ActionHandlerBuilder<typeof actionBuilder> = (
  locals
) => {
  return {
    type: actionBuilder.type,
    async handle (action) {
      const { cloudVaultManager: cvm, syncManager } = locals

      // Call the internal function
      await syncManager.sync({ timestamps: cvm.timestamps })

      return { response: undefined, status: 200 }
    }
  }
}
