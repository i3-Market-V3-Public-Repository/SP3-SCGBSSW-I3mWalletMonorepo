import { WalletLink } from './wallet-link'
import { WalletIdentityData } from './authentication'


export interface IWalletConnector {
  discovery(): Promise<WalletIdentityData[]>
  authenticate(walletId: WalletIdentityData): Promise<WalletLink>

  on(channel: 'discovery'): void
}

export class WalletConnector {
  
}
