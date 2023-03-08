import {
  deleteIdentityAction
} from '@wallet/lib'
import { ActionError, ActionHandlerBuilder } from '@wallet/main/internal'

export const deleteIdentity: ActionHandlerBuilder<typeof deleteIdentityAction> = (
  locals
) => {
  return {
    type: deleteIdentityAction.type,
    async handle (action) {
      let identityDid: string
      if (action.payload !== undefined) {
        identityDid = action.payload
      } else {
        throw new ActionError('Not implemented yet', action)
      }

      const { walletFactory, sharedMemoryManager } = locals

      // Verify wallet
      if (!walletFactory.hasWalletSelected) {
        locals.toast.show({
          message: 'Wallet not selected',
          details: 'You must select a wallet before deleteing identities',
          type: 'warning'
        })
        return { response: undefined, status: 500 }
      }
      await walletFactory.wallet.deleteIdentity(identityDid)

      // Update state
      const identities = await walletFactory.wallet.getIdentities()
      sharedMemoryManager.update((mem) => ({ ...mem, identities }))

      return { response: undefined }
    }
  }
}
