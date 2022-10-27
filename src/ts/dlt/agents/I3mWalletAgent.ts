import { HttpInitiatorTransport, Session } from '@i3m/wallet-protocol/types'
import { EthersIoAgent } from './EthersIoAgent'
import { DltConfig } from '../../types'

/**
 * A NRP DLT agent using ethers.io for reading from the smart contract and the i3m-wallet for signing transactions to the smart contract
 */
export class I3mWalletAgent extends EthersIoAgent {
  session: Session<HttpInitiatorTransport>
  did: string

  constructor (session: Session<HttpInitiatorTransport>, did: string, dltConfig: Partial<DltConfig> & Pick<DltConfig, 'rpcProviderUrl'>) {
    super(dltConfig)
    this.session = session
    this.did = did
  }
}
