import {
  deleteResourceAction
} from '@wallet/lib'
import { ActionError, ActionHandlerBuilder } from '@wallet/main/internal'

export const deleteResource: ActionHandlerBuilder<typeof deleteResourceAction> = (
  locals
) => {
  return {
    type: deleteResourceAction.type,
    async handle (action) {
      let resourceId: string
      if (action.payload !== undefined) {
        resourceId = action.payload
      } else {
        throw new ActionError('Not implemented yet', action)
      }

      const { walletFactory, sharedMemoryManager } = locals

      // Verify wallet
      if (!walletFactory.hasWalletSelected) {
        locals.toast.show({
          message: 'Wallet not selected',
          details: 'You must select a wallet before deleting resources',
          type: 'warning'
        })
        return { response: undefined, status: 500 }
      }
      await walletFactory.wallet.deleteResource(resourceId)

      // Update state
      const resources = await walletFactory.wallet.getResources()
      sharedMemoryManager.update((mem) => ({ ...mem, resources }))

      return { response: undefined }
    }
  }
}
