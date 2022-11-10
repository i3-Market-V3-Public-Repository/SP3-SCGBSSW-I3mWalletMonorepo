import { getSecretFromLedger as getSecret } from '../secret'
import { I3mServerWalletAgent } from '../I3mServerWalletAgent'
import { NrpDltAgentDest } from './NrpDltAgentDest'

/**
 * A DLT agent for the NRP dest using the i3-MARKET server Wallet.
 */
export class I3mServerWalletAgentDest extends I3mServerWalletAgent implements NrpDltAgentDest {
  async getSecretFromLedger (secretLength: number, signerAddress: string, exchangeId: string, timeout: number): Promise<{ hex: string, iat: number }> {
    await this.initialized
    return await getSecret(this.contract, signerAddress, exchangeId, timeout, secretLength)
  }
}
