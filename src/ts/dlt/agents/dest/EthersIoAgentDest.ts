import { getSecretFromLedger as getSecret } from '../secret.js'
import { EthersIoAgent } from '../EthersIoAgent.js'
import { NrpDltAgentDest } from './NrpDltAgentDest.js'

/**
 * A DLT agent for the NRP dest using ethers.io.
 */
export class EthersIoAgentDest extends EthersIoAgent implements NrpDltAgentDest {
  async getSecretFromLedger (secretLength: number, signerAddress: string, exchangeId: string, timeout: number): Promise<{ hex: string, iat: number }> {
    await this.initialized
    return await getSecret(this.contract, signerAddress, exchangeId, timeout, secretLength)
  }
}
