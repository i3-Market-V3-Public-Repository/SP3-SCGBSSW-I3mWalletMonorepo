
import { JSONObject } from './json-object'

export interface WalletInfo {
  name: string
  package: string
  store: string
  args: JSONObject
}

export interface WalletSettings {
  current?: string // Module name of the current wallet
  wallets: {
    [walletName: string]: WalletInfo
  }
  packages: string[]
}

export interface Settings {
  wallet: WalletSettings
}

export function createDefaultSettings (): Settings {
  return {
    wallet: {
      wallets: {},
      packages: ['@i3-market/sw-wallet']
    }
  }
}
