import { ethers } from 'ethers'
import { DltConfig } from '../../types.js'
import { defaultDltConfig } from '../defaultDltConfig.js'
import { NrpDltAgent } from './NrpDltAgent.js'

/**
 * A NRP DLT agent using the well known ethers.io library and, if required, wallet (for publishing secrets)
 */
export class EthersIoAgent extends NrpDltAgent {
  dltConfig!: DltConfig
  contract!: ethers.Contract
  provider!: ethers.providers.Provider
  initialized: Promise<boolean>

  constructor (dltConfig: (Partial<DltConfig> & Pick<DltConfig, 'rpcProviderUrl'>) | Promise<(Partial<DltConfig> & Pick<DltConfig, 'rpcProviderUrl'>)>) {
    super()
    this.initialized = new Promise((resolve, reject) => {
      if (dltConfig !== null && typeof dltConfig === 'object' && typeof (dltConfig as any).then === 'function') {
        (dltConfig as Promise<(Partial<DltConfig> & Pick<DltConfig, 'rpcProviderUrl'>)>).then(dltConfig2 => {
          this.dltConfig = {
            ...defaultDltConfig,
            ...dltConfig2
          }
          this.provider = new ethers.providers.JsonRpcProvider(this.dltConfig.rpcProviderUrl)

          this.contract = new ethers.Contract(this.dltConfig.contract.address, this.dltConfig.contract.abi, this.provider)
          resolve(true)
        }).catch((reason) => reject(reason))
      } else {
        this.dltConfig = {
          ...defaultDltConfig,
          ...(dltConfig as Partial<DltConfig> & Pick<DltConfig, 'rpcProviderUrl'>)
        }
        this.provider = new ethers.providers.JsonRpcProvider(this.dltConfig.rpcProviderUrl)

        this.contract = new ethers.Contract(this.dltConfig.contract.address, this.dltConfig.contract.abi, this.provider)

        resolve(true)
      }
    })
  }

  async getContractAddress (): Promise<string> {
    await this.initialized
    return this.contract.address
  }
}
