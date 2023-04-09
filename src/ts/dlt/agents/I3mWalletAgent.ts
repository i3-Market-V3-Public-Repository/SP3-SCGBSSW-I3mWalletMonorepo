import { WalletApi } from '@i3m/wallet-protocol-api/types'
import { DltConfig } from '../../types.js'
import { EthersIoAgent } from './EthersIoAgent.js'

/**
 * A NRP DLT agent using ethers.io for reading from the smart contract and the i3m-wallet for signing transactions to the smart contract
 */
export class I3mWalletAgent extends EthersIoAgent {
  wallet: WalletApi
  did: string

  constructor (wallet: WalletApi, did: string, dltConfig?: Partial<Omit<DltConfig, 'rpcProviderUrl'>>) {
    const dltConfigPromise: Promise<Partial<Omit<DltConfig, 'rpcProviderUrl'>> & Pick<DltConfig, 'rpcProviderUrl'>> = new Promise((resolve, reject) => {
      wallet.providerinfo.get().then((providerInfo) => {
        const rpcProviderUrl = providerInfo.rpcUrl
        if (rpcProviderUrl === undefined) {
          reject(new Error('wallet is not connected to RPC endpoint'))
        } else {
          resolve({
            ...dltConfig,
            rpcProviderUrl
          })
        }
      }).catch((reason) => { reject(reason) })
    })
    super(dltConfigPromise)
    this.wallet = wallet
    this.did = did
  }
}
