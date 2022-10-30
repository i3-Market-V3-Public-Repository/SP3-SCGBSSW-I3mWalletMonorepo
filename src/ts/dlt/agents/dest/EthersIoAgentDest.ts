import { getSecretFromLedger as getSecret } from '../secret'
import { EthersIoAgent } from '../EthersIoAgent'
import { NrpDltAgentDest } from './NrpDltAgentDest'

/**
 * A DLT agent for the NRP dest using ethers.io.
 */
export class EthersIoAgentDest extends EthersIoAgent implements NrpDltAgentDest {
  async getSecretFromLedger (signerAddress: string, exchangeId: string, timeout: number): Promise<{ hex: string, iat: number }> {
    return await getSecret(this.contract, signerAddress, exchangeId, timeout)
  }
}
