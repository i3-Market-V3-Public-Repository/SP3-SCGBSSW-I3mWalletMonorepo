import {
  didJwtVerifyAction as actionBuilder
} from '@wallet/lib'
import { ActionHandlerBuilder } from '../action-handler'

export const verifyJWT: ActionHandlerBuilder<typeof actionBuilder> = (
  locals
) => {
  return {
    type: actionBuilder.type,
    async handle (action) {
      const { walletFactory } = locals

      // Create identity
      const response = await walletFactory.wallet.didJwtVerify(action.payload.body)
      return { response, status: 200 }
    }
  }
}
