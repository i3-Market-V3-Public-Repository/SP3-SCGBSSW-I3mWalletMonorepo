import { WalletOptions, BaseWalletModel } from '@i3-market/base-wallet'

export interface HDData {
  mnemonic: string
  accounts: number
}

export interface SwWalletModel extends BaseWalletModel {
  hdData: HDData
}

export interface SwWalletOptions extends WalletOptions<SwWalletModel> {

}
