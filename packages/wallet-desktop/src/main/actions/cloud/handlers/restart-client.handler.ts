import {
  clientRestartAction as actionBuilder
} from '@wallet/lib'
import { ActionHandlerBuilder } from '@wallet/main/internal'

export const restartClient: ActionHandlerBuilder<typeof actionBuilder> = (
  locals
) => {
  return {
    type: actionBuilder.type,
    async handle (action) {
      const { cloudVaultManager } = locals

      // Call the internal function
      await cloudVaultManager.restartClient()

      return { response: undefined, status: 200 }
    }
  }
}
