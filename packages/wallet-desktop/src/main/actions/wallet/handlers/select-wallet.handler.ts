import {
  selectWalletAction
} from '@wallet/lib'
import { ActionError, ActionHandlerBuilder } from '@wallet/main/internal'

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

      if (wallet === sharedMemoryManager.memory.settings.wallet.current) {
        return { response: wallet }
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
        },
        identities: {},
        resources: {}
      }))

      return { response: wallet }
    }
  }
}
