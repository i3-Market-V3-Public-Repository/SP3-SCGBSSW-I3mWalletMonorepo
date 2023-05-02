import {
  createWalletAction
} from '@wallet/lib'
import { ActionHandlerBuilder } from '@wallet/main/internal'

export const createWallet: ActionHandlerBuilder<typeof createWalletAction> = (
  locals
) => {
  return {
    type: createWalletAction.type,
    async handle () {
      const { walletFactory } = locals
      const wallet = await walletFactory.createWallet()
      return { response: wallet, status: 201 }
    }
  }
}
