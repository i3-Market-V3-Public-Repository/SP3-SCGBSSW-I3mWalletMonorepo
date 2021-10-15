import { WalletOptionsSettings, BaseWalletModel } from '@i3-market/base-wallet'

export type KeyType = 'Secp256k1'

export interface Key {
  kid: string
  type: KeyType
  publicKeyHex: string
  privateKeyHex: string
}

export interface BokWalletModel extends BaseWalletModel {
  keys: {
    [kid: string]: Key
  }
}

export interface BokWalletOptions extends WalletOptionsSettings<BokWalletModel> {

}
