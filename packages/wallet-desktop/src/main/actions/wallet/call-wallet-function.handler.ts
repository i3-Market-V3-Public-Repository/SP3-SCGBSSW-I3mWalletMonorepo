import {
  callWalletFunctionAction
} from '@wallet/lib'
import { ActionHandlerBuilder } from '../action-handler'

export const callWalletFunction: ActionHandlerBuilder<typeof callWalletFunctionAction> = (
  locals
) => {
  return {
    type: callWalletFunctionAction.type,
    async handle (action) {
      const { walletFactory } = locals

      // Call the internal function
      await walletFactory.wallet.call(action.payload)

      // Refresh all sharedMemory
      await walletFactory.refreshWalletData()

      return { response: undefined, status: 200 }
    }
  }
}
