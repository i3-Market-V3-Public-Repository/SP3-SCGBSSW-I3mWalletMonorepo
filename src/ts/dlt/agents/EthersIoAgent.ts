import { ethers } from 'ethers'
import { defaultDltConfig } from '..'
import { DltConfig } from '../../types'
import { NrpDltAgent } from './NrpDltAgent'

/**
 * A NRP DLT agent using the well known ethers.io library and, if required, wallet (for publishing secrets)
 */
export class EthersIoAgent extends NrpDltAgent {
  dltConfig: DltConfig
  contract: ethers.Contract
  provider: ethers.providers.Provider

  constructor (dltConfig: Partial<DltConfig> & Pick<DltConfig, 'rpcProviderUrl'>) {
    super()

    this.dltConfig = {
      ...defaultDltConfig,
      ...dltConfig
    }
    this.provider = new ethers.providers.JsonRpcProvider(this.dltConfig.rpcProviderUrl)

    this.contract = new ethers.Contract(this.dltConfig.contract.address, this.dltConfig.contract.abi, this.provider)
  }

  async getContractAddress (): Promise<string> {
    return this.contract.address
  }
}
