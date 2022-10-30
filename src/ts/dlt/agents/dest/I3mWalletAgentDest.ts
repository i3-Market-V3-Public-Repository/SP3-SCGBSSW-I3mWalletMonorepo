import { getSecretFromLedger as getSecret } from '../secret'
import { I3mWalletAgent } from '../I3mWalletAgent'
import { NrpDltAgentDest } from './NrpDltAgentDest'

/**
 * A DLT agent for the NRP dest using the i3M-Wallet
 */
export class I3mWalletAgentDest extends I3mWalletAgent implements NrpDltAgentDest {
  async getSecretFromLedger (signerAddress: string, exchangeId: string, timeout: number): Promise<{ hex: string, iat: number }> {
    await this.initialized
    return await getSecret(this.contract, signerAddress, exchangeId, timeout)
  }
}
