import { ethers } from 'ethers'
import { defaultDltConfig } from '..'
import { DltConfig } from '../../types'
import { WalletAgent } from './WalletAgent'

/**
 * A ledger signer using an ethers.io Wallet.
 */
export class EthersWalletAgent extends WalletAgent {
  dltConfig: DltConfig
  contract: ethers.Contract
  provider: ethers.providers.Provider

  constructor (dltConfig?: Partial<DltConfig>) {
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
