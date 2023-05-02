import {
  selectWalletAction
} from '@wallet/lib'
import { ActionHandlerBuilder } from '@wallet/main/internal'

export const selectWallet: ActionHandlerBuilder<typeof selectWalletAction> = (
  locals
) => {
  return {
    type: selectWalletAction.type,
    async handle (action) {
      const { walletFactory } = locals
      const walletName = await walletFactory.selectWallet(action.payload?.wallet)
      return { response: walletName }
    }
  }
}
