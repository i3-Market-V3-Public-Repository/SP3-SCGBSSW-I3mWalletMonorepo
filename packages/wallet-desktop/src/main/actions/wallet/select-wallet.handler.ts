import {
  selectWalletAction
} from '@wallet/lib'
import { ActionError } from '../action-error'
import { ActionHandlerBuilder } from '../action-handler'

export const selectWallet: ActionHandlerBuilder<typeof selectWalletAction> = (
  locals
) => {
  return {
    type: selectWalletAction.type,
    async handle (action) {
      const { walletFactory, sharedMemoryManager, dialog } = locals
      let wallet = action.payload?.wallet
      if (wallet === undefined) {
        wallet = await dialog.select({ values: walletFactory.walletNames })
      }

      if (wallet === undefined) {
        throw new ActionError('Cannot change wallet: no wallet selected', action)
      }

      sharedMemoryManager.update((mem) => ({
        ...mem,
        settings: {
          ...mem.settings,
          wallet: {
            ...mem.settings.wallet,
            current: wallet
          }
        }
      }))

      return { response: wallet }
    }
  }
}
