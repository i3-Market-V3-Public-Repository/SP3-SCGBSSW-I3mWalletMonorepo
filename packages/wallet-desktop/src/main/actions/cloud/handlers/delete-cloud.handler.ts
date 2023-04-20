import {
  deleteCloudAction as actionBuilder
} from '@wallet/lib'
import { ActionHandlerBuilder } from '@wallet/main/internal'

export const deleteCloud: ActionHandlerBuilder<typeof actionBuilder> = (
  locals
) => {
  return {
    type: actionBuilder.type,
    async handle (action) {
      const { cloudVaultManager } = locals

      // Call the internal function
      await cloudVaultManager.delete()

      return { response: undefined, status: 200 }
    }
  }
}
