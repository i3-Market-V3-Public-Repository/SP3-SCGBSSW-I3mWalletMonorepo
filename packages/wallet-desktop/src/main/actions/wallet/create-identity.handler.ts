import {
  createIdentityAction
} from '@wallet/lib'
import { ActionError } from '../action-error'
import { ActionHandlerBuilder } from '../action-handler'

export const createIdentity: ActionHandlerBuilder<typeof createIdentityAction> = (
  locals
) => {
  return {
    type: createIdentityAction.type,
    async handle (action) {
      const { dialog, walletFactory } = locals
      let alias: string | undefined = action.payload.alias

      if (alias === undefined) {
        alias = await dialog.text({
          message: 'Input an alias for the identity'
        })
      }

      if (alias === undefined) {
        throw new ActionError('Cannot create identity. Dialog cancelled', action)
      }

      // Create identity
      if (!walletFactory.hasWalletSelected) {
        locals.toast.show({
          message: 'Wallet not selected',
          details: 'You must select a wallet before creating identities',
          type: 'warning'
        })
        return { response: undefined, status: 500 }
      }
      const response = await walletFactory.wallet.identityCreate({ alias })

      // Update state
      await walletFactory.refreshWalletData()

      return { response, status: 201 }
    }
  }
}
