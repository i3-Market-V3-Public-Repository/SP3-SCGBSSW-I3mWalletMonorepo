import {
  deleteWalletAction as actionBuilder
} from '@wallet/lib'
import { ActionError, ActionHandlerBuilder } from '@wallet/main/internal'

export const deleteWallet: ActionHandlerBuilder<typeof actionBuilder> = (
  locals
) => {
  return {
    type: actionBuilder.type,
    async handle (action) {
      let walletName: string
      if (action.payload !== undefined) {
        walletName = action.payload
      } else {
        throw new ActionError('Not implemented yet', action)
      }

      const { walletFactory, dialog } = locals
      const confirmation = await dialog.confirmation({
        message: `All data for the wallet '${walletName}' will be deleted. Are you sure?`
      })
      if (confirmation !== true) {
        return { response: undefined, status: 403 }
      }

      await walletFactory.deleteWallet(walletName)

      return { response: undefined }
    }
  }
}
