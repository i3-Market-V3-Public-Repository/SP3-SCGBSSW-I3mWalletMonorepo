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
      const { sharedMemoryManager, walletFactory } = locals

      // Call the internal function
      await walletFactory.wallet.call(action.payload)

      // Refresh all sharedMemory
      const identities = await walletFactory.wallet.getIdentities()
      const resources = await walletFactory.wallet.getResources()
      sharedMemoryManager.update((mem) => ({ ...mem, identities, resources }))

      return { response: undefined, status: 200 }
    }
  }
}
