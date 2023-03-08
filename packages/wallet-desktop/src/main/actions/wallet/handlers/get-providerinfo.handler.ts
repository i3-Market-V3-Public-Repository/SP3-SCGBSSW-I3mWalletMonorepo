import {
  getProviderinfoAction as actionBuilder
} from '@wallet/lib'
import { ActionHandlerBuilder } from '@wallet/main/internal'

export const getProviderinfo: ActionHandlerBuilder<typeof actionBuilder> = (
  locals
) => {
  return {
    type: actionBuilder.type,
    async handle (action) {
      const { walletFactory } = locals

      // Create identity
      const response = await walletFactory.wallet.providerinfoGet()
      return { response, status: 200 }
    }
  }
}
