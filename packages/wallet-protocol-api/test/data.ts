import { BaseWallet } from '@i3m/base-wallet/types'
import { WalletApi } from '#pkg'

interface Identity {
  did: string
  address?: string
}

export interface Data {
  api: WalletApi
  wallet: BaseWallet<any>

  // basic data
  validator: Identity
  signer: Identity

  // identities
  user: Identity
}

const data: Data = {} as any
export default data
