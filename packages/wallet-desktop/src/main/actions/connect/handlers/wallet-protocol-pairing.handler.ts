import {
  walletProtocolPairingAction
} from '@wallet/lib'
import { ActionHandlerBuilder } from '@wallet/main/internal'

export const walletProtocolPairing: ActionHandlerBuilder<typeof walletProtocolPairingAction> = (
  locals
) => {
  return {
    type: walletProtocolPairingAction.type,
    async handle (action) {
      const { connectManager } = locals

      // Call the internal function
      connectManager.startWalletProtocol()

      return { response: undefined, status: 200 }
    }
  }
}
