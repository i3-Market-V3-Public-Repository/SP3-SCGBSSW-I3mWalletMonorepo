import type { ServerWallet } from '@i3m/server-wallet'
import { DltConfig } from '../../types.js'
import { EthersIoAgent } from './EthersIoAgent.js'

/**
 * A NRP DLT agent using ethers.io for reading from the smart contract and the i3m-serverwallet for signing transactions to the smart contract
 */
export class I3mServerWalletAgent extends EthersIoAgent {
  wallet: ServerWallet
  did: string

  constructor (serverWallet: ServerWallet, did: string, dltConfig?: Partial<Omit<DltConfig, 'rpcProviderUrk'>>) {
    const dltConfigPromise: Promise<Partial<Omit<DltConfig, 'rpcProviderUrl'>> & Pick<DltConfig, 'rpcProviderUrl'>> = new Promise((resolve, reject) => {
      serverWallet.providerinfoGet().then((providerInfo) => {
        const rpcProviderUrl = providerInfo.rpcUrl
        if (rpcProviderUrl === undefined) {
          reject(new Error('wallet is not connected to RPC endpoint'))
        } else {
          resolve({
            ...dltConfig,
            rpcProviderUrl: (typeof rpcProviderUrl === 'string') ? rpcProviderUrl : rpcProviderUrl[0]
          })
        }
      }).catch((reason) => { reject(reason) })
    })
    super(dltConfigPromise)
    this.wallet = serverWallet
    this.did = did
  }
}
