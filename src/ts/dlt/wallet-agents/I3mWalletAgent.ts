import { HttpInitiatorTransport, Session } from '@i3m/wallet-protocol'
import { EthersWalletAgent } from './EthersWalletAgent'
import { DltConfig } from '../../types'

export class I3mWalletAgent extends EthersWalletAgent {
  session: Session<HttpInitiatorTransport>
  did: string

  constructor (session: Session<HttpInitiatorTransport>, did: string, dltConfig?: Partial<DltConfig>) {
    super(dltConfig)
    this.session = session
    this.did = did
  }
}
