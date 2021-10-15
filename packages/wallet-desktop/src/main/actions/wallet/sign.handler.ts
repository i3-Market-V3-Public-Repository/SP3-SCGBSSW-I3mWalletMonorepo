import {
  signAction
} from '@wallet/lib'
import { ActionHandlerBuilder } from '../action-handler'

export const sign: ActionHandlerBuilder<typeof signAction> = (
  locals
) => {
  return {
    type: signAction.type,
    async handle (action) {
      const { walletFactory } = locals

      // Create identity
      const response = await walletFactory.wallet.identitySign(action.payload.signer, action.payload.body)
      return { response, status: 200 }
    }
  }
}
