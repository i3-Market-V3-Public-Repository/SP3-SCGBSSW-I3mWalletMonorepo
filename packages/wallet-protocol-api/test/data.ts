import { BaseWallet } from '@i3m/base-wallet'

interface Identity {
  did: string
  address?: string
}

export interface Data {
  api: _pkg.WalletApi
  wallet: BaseWallet<any>

  // basic data
  validator: Identity
  signer: Identity

  // identities
  user: Identity
}

const data: Data = {} as any
export default data
