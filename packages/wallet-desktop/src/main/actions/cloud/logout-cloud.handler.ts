import {
  logoutCloudAction as actionBuilder
} from '@wallet/lib'
import { ActionHandlerBuilder } from '../action-handler'

export const logoutCloud: ActionHandlerBuilder<typeof actionBuilder> = (
  locals
) => {
  return {
    type: actionBuilder.type,
    async handle (action) {
      const { cloudVaultManager } = locals

      // Call the internal function
      await cloudVaultManager.logout()

      return { response: undefined, status: 200 }
    }
  }
}
