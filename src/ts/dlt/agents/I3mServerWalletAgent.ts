import { EthersIoAgent } from './EthersIoAgent'
import { DltConfig } from '../../types'
import { ServerWallet } from '@i3m/server-wallet/types'

/**
 * A NRP DLT agent using ethers.io for reading from the smart contract and the i3m-serverwallet for signing transactions to the smart contract
 */
export class I3mServerWalletAgent extends EthersIoAgent {
  wallet: ServerWallet
  did: string

  constructor (serverWallet: ServerWallet, did: string, dltConfig?: Partial<DltConfig>) {
    const rpcProviderUrl = (serverWallet as any).providersData[(serverWallet as any).provider].rpcUrl

    super({ ...dltConfig, rpcProviderUrl })
    this.wallet = serverWallet
    this.did = did
  }
}
